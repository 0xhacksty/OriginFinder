#!/usr/bin/env python3
"""
Multi-Source Origin IP Discovery Tool
Aggregates passive intelligence from DNS, CT logs, Shodan, Censys, and RDAP
to identify probable origin IPs behind CDNs with explainable evidence.
"""

import argparse
import json
import sys
import time
import sqlite3
import hashlib
import os
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright, Error as PlaywrightError
import difflib
from urllib.parse import urlparse

# Configuration
CONFIG = {
    'cache_ttl_dns': 3600,  # 1 hour
    'cache_ttl_passive': 259200,  # 72 hours
    'cache_ttl_ct': 259200,  # 72 hours
    'confidence_threshold': 75,
    'high_confidence_threshold': 85,
    'min_independent_signals': 2,
    'temporal_freshness_hours': 72,
    'max_workers': 5,
    'api_timeout': 15,
    'verification_timeout': 10,  # Content verification timeout
    'levenshtein_threshold': 0.85,  # 85% similarity = match
    'verify_max_workers': 10,  # Parallel verification threads
}

# Known CDN ASNs and providers (add more as needed)
CDN_ASNS = {
    13335: 'Cloudflare',
    16625: 'Akamai',
    54113: 'Fastly',
    19551: 'Incapsula',
    20940: 'Akamai',
    16509: 'AWS-CloudFront',
    15169: 'Google',
    8075: 'Microsoft-Azure',
}

# Scoring weights
SCORE_WEIGHTS = {
    'direct_origin_record': 40,
    'recent_passive_dns': 25,
    'cert_san_match': 30,
    'content_hash_match': 35,
    'non_cdn_asn': 20,
    'shodan_match': 20,
    'ptr_match': 10,
    'old_passive_dns': 5,
    'cdn_penalty': -50,
}


def load_api_keys(config_file: str = 'config.yaml') -> Dict[str, str]:
    """
    Load API keys from environment (.env + process env), with optional config fallback.
    """
    api_keys = {}

    # Load .env manually to avoid extra dependency.
    env_path = Path('.env')
    if env_path.exists():
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and value and key not in os.environ:
                        os.environ[key] = value
        except Exception as e:
            print(f"[!] Error reading .env file: {str(e)}")

    env_mapping = {
        'SHODAN_API_KEY': 'shodan',
        'CENSYS_API_ID': 'censys_id',
        'CENSYS_API_SECRET': 'censys_secret',
        'DNSDB_API_KEY': 'dnsdb',
        'PASSIVETOTAL_API_KEY': 'passivetotal',
        'SECURITYTRAILS_API_KEY': 'securitytrails',
    }

    # Prefer environment variables.
    for env_key, internal_key in env_mapping.items():
        value = os.getenv(env_key, '').strip()
        if value:
            api_keys[internal_key] = value

    if api_keys:
        print(f"[+] Loaded {len(api_keys)} API key(s) from environment")
        return api_keys

    # Optional fallback to legacy config file.
    config_path = Path(config_file)
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")

                        if value:
                            if key == 'shodan_api_key':
                                api_keys['shodan'] = value
                            elif key == 'censys_api_id':
                                api_keys['censys_id'] = value
                            elif key == 'censys_api_secret':
                                api_keys['censys_secret'] = value
                            elif key == 'dnsdb_api_key':
                                api_keys['dnsdb'] = value
                            elif key == 'passivetotal_api_key':
                                api_keys['passivetotal'] = value
                            elif key == 'securitytrails_api_key':
                                api_keys['securitytrails'] = value

            if api_keys:
                print(f"[+] Loaded {len(api_keys)} API key(s) from {config_file}")
            else:
                print("[!] No API keys found in environment or config file (running with free sources only)")
            return api_keys
        except Exception as e:
            print(f"[!] Error reading config file: {str(e)}")
            return {}

    print("[!] No API keys found in environment (running with free sources only)")
    return {}


class CacheDB:
    """Thread-safe SQLite-based cache for API responses"""
    
    def __init__(self, db_path='origin_finder.db'):
        self.db_path = db_path
        self._init_db()
    
    def _get_connection(self):
        """Get a connection for the current thread"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        conn = self._get_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                timestamp INTEGER,
                ttl INTEGER
            )
        ''')
        conn.commit()
        conn.close()
    
    def get(self, key: str) -> Optional[dict]:
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                'SELECT value, timestamp, ttl FROM cache WHERE key = ?', (key,)
            )
            row = cursor.fetchone()
            if row:
                if time.time() - row['timestamp'] < row['ttl']:
                    return json.loads(row['value'])
                else:
                    conn.execute('DELETE FROM cache WHERE key = ?', (key,))
                    conn.commit()
            return None
        finally:
            conn.close()
    
    def set(self, key: str, value: dict, ttl: int):
        conn = self._get_connection()
        try:
            conn.execute(
                'INSERT OR REPLACE INTO cache (key, value, timestamp, ttl) VALUES (?, ?, ?, ?)',
                (key, json.dumps(value), int(time.time()), ttl)
            )
            conn.commit()
        finally:
            conn.close()
    
    def close(self):
        # No persistent connection to close
        pass


class ContentVerifier:
    """Verify candidate IPs by comparing response content and headers"""
    
    def __init__(self, cache: CacheDB):
        self.cache = cache
        self.session = requests.Session()
        self.session.timeout = CONFIG['verification_timeout']
    
    def _normalize_content(self, content: str) -> str:
        """Normalize content for comparison (remove whitespace, comments)"""
        if not content:
            return ""
        # Remove extra whitespace
        content = ' '.join(content.split())
        # Remove HTML comments
        import re
        content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
        return content
    
    def _calculate_similarity(self, original: str, candidate: str) -> float:
        """Calculate Levenshtein similarity ratio (0-1)"""
        if not original or not candidate:
            return 0.0
        seq = difflib.SequenceMatcher(None, original, candidate)
        return seq.ratio()
    
    def _extract_fingerprint(self, response: requests.Response) -> Dict:
        """Extract server fingerprint from response headers"""
        return {
            'server': response.headers.get('Server', ''),
            'x_powered_by': response.headers.get('X-Powered-By', ''),
            'x_frame_options': response.headers.get('X-Frame-Options', ''),
            'content_type': response.headers.get('Content-Type', ''),
            'status_code': response.status_code,
            'content_length': len(response.content),
        }
    
    def _fetch_content(self, url: str) -> Optional[Tuple[str, Dict]]:
        """Fetch content from URL with fallback for blocked access"""
        try:
            # Try with host header
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = self.session.get(url, headers=headers, verify=False, allow_redirects=True)
            fingerprint = self._extract_fingerprint(response)
            return (response.text, fingerprint)
        except Exception:
            # Fallback: try without user agent
            try:
                response = self.session.get(url, verify=False, allow_redirects=True, timeout=5)
                fingerprint = self._extract_fingerprint(response)
                return (response.text, fingerprint)
            except Exception:
                return None
    
    def verify_candidate(self, ip: str, original_url: str, original_content: str, original_fingerprint: Dict) -> Dict:
        """Verify a single candidate IP against original content"""
        verification = {
            'ip': ip,
            'verified': False,
            'similarity_score': 0.0,
            'content_match': False,
            'header_match': False,
            'verification_error': None,
            'url_tested': None
        }
        
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            url = f"{protocol}://{ip}/"
            verification['url_tested'] = url
            
            try:
                result = self._fetch_content(url)
                if not result:
                    continue
                
                content, fingerprint = result
                
                # Calculate content similarity
                norm_original = self._normalize_content(original_content)
                norm_candidate = self._normalize_content(content)
                similarity = self._calculate_similarity(norm_original, norm_candidate)
                verification['similarity_score'] = round(similarity, 3)
                
                # Check if content matches threshold
                if similarity >= CONFIG['levenshtein_threshold']:
                    verification['content_match'] = True
                    verification['verified'] = True
                    break
                
                # Check header fingerprint match
                if self._headers_match(original_fingerprint, fingerprint):
                    verification['header_match'] = True
                    if similarity > 0.7:  # Even 70% with matching headers is good
                        verification['verified'] = True
                        break
            
            except Exception as e:
                verification['verification_error'] = str(e)[:50]
        
        return verification
    
    def _headers_match(self, orig: Dict, cand: Dict) -> bool:
        """Check if headers match significantly"""
        matches = 0
        total = 0
        
        for key in ['server', 'x_powered_by', 'content_type']:
            total += 1
            if orig.get(key) and cand.get(key):
                if orig[key].lower() == cand[key].lower():
                    matches += 1
        
        # Status code match is strong signal
        if orig.get('status_code') == cand.get('status_code'):
            matches += 1
        total += 1
        
        return matches / total >= 0.5
    
    def verify_all_candidates(self, candidates: List[Dict], original_url: str) -> Dict[str, Dict]:
        """Verify all candidates in parallel"""
        print(f"\n[*] Fetching original content from: {original_url}")
        
        original_result = self._fetch_content(original_url)
        if not original_result:
            print(f"[!] Failed to fetch original content from {original_url}")
            return {}
        
        original_content, original_fingerprint = original_result
        print(f"[+] Original content fetched ({len(original_content)} bytes)")
        
        verification_map = {}
        total = len(candidates)
        completed = 0
        
        print(f"\n[*] Verifying {total} candidate IP(s) in parallel...")
        
        with ThreadPoolExecutor(max_workers=CONFIG['verify_max_workers']) as executor:
            futures = {
                executor.submit(
                    self.verify_candidate,
                    cand['ip'],
                    original_url,
                    original_content,
                    original_fingerprint
                ): cand['ip']
                for cand in candidates
            }
            
            for future in as_completed(futures):
                completed += 1
                ip = futures[future]
                
                try:
                    result = future.result()
                    verification_map[ip] = result
                    
                    if result['verified']:
                        print(f"[+] {completed}/{total}: VERIFIED {ip} (similarity: {result['similarity_score']})")
                    else:
                        print(f"[*] {completed}/{total}: {ip} (similarity: {result['similarity_score']})")
                except Exception as e:
                    print(f"[!] {completed}/{total}: Error verifying {ip}: {str(e)[:50]}")
        
        print(f"\n[+] Verification complete: {len([v for v in verification_map.values() if v['verified']])}/{total} verified")
        return verification_map


class OriginIPFinder:
    """Main orchestrator for origin IP discovery"""
    
    def __init__(self, api_keys: dict = None, ipv4_only: bool = True):
        self.api_keys = api_keys or {}
        self.cache = CacheDB()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.ipv4_only = ipv4_only
        self.verifier = ContentVerifier(self.cache)
    
    def find_origin_ips(self, domain: str) -> List[Dict]:
        """Main entry point - find and score candidate origin IPs"""
        print(f"[*] Starting origin IP discovery for: {domain}")
        
        # Collect data from all sources in parallel
        candidates = {}
        
        with ThreadPoolExecutor(max_workers=CONFIG['max_workers']) as executor:
            futures = {
                executor.submit(self._collect_live_dns, domain): 'live_dns',
                executor.submit(self._collect_passive_dns, domain): 'passive_dns',
                executor.submit(self._collect_ct_logs, domain): 'ct_logs',
                executor.submit(self._collect_shodan, domain): 'shodan',
                executor.submit(self._collect_censys, domain): 'censys',
            }
            
            for future in as_completed(futures):
                source = futures[future]
                try:
                    result = future.result()
                    self._merge_candidates(candidates, result, source)
                    print(f"[+] Collected data from: {source}")
                except Exception as e:
                    print(f"[!] Error collecting from {source}: {str(e)}")
        
        # Enrich candidates with RDAP/ASN data
        self._enrich_with_rdap(candidates)
        
        # Score and rank
        scored_ips = self._score_candidates(candidates, domain)
        
        # Sort by score descending
        scored_ips.sort(key=lambda x: x['score'], reverse=True)
        
        return scored_ips
    
    def _collect_live_dns(self, domain: str) -> Dict[str, List]:
        """Query live DNS for A/AAAA records"""
        cache_key = f"dns_live_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {'ips': []}
        
        for record_type in ['A', 'AAAA']:
            try:
                answers = self.resolver.resolve(domain, record_type)
                for rdata in answers:
                    result['ips'].append({
                        'ip': str(rdata),
                        'type': record_type,
                        'ttl': answers.rrset.ttl,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
            except Exception:
                pass
        
        # Try common origin subdomains
        for prefix in ['origin', 'direct', 'source']:
            try:
                origin_domain = f"{prefix}.{domain}"
                answers = self.resolver.resolve(origin_domain, 'A')
                for rdata in answers:
                    result['ips'].append({
                        'ip': str(rdata),
                        'type': 'A',
                        'ttl': answers.rrset.ttl,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'hostname': origin_domain,
                        'is_origin_subdomain': True
                    })
            except Exception:
                pass
        
        self.cache.set(cache_key, result, CONFIG['cache_ttl_dns'])
        return result
    
    def _collect_passive_dns(self, domain: str) -> Dict[str, List]:
        """Query passive DNS sources (placeholder - requires API keys)"""
        # This would integrate with DNSDB/PassiveTotal/SecurityTrails
        # For now, return empty structure
        return {'ips': []}
    
    def _collect_ct_logs(self, domain: str) -> Dict[str, List]:
        """Query Certificate Transparency logs via crt.sh"""
        cache_key = f"ct_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {'certs': [], 'ips': []}
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=CONFIG['api_timeout'])
            
            if response.status_code == 200:
                certs = response.json()
                seen_ips = set()
                
                for cert in certs[:50]:  # Limit to recent 50
                    common_name = cert.get('common_name', '')
                    name_value = cert.get('name_value', '')
                    
                    result['certs'].append({
                        'common_name': common_name,
                        'sans': name_value.split('\n'),
                        'issuer': cert.get('issuer_name', ''),
                        'not_before': cert.get('not_before', ''),
                        'serial': cert.get('serial_number', '')
                    })
                    
                    # Try to resolve SANs to IPs
                    for san in name_value.split('\n'):
                        san = san.strip()
                        if san and not san.startswith('*') and san not in seen_ips:
                            try:
                                answers = self.resolver.resolve(san, 'A')
                                for rdata in answers:
                                    ip = str(rdata)
                                    if ip not in seen_ips:
                                        result['ips'].append({
                                            'ip': ip,
                                            'hostname': san,
                                            'source': 'ct_san_resolution'
                                        })
                                        seen_ips.add(ip)
                            except Exception:
                                pass
        
        except Exception as e:
            print(f"[!] CT logs error: {str(e)}")
        
        self.cache.set(cache_key, result, CONFIG['cache_ttl_ct'])
        return result
    
    def _collect_shodan(self, domain: str) -> Dict[str, List]:
        """Query Shodan API (requires API key)"""
        if 'shodan' not in self.api_keys:
            return {'ips': []}
        
        cache_key = f"shodan_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {'ips': []}
        
        try:
            url = f"https://api.shodan.io/dns/domain/{domain}"
            params = {'key': self.api_keys['shodan']}
            response = requests.get(url, params=params, timeout=CONFIG['api_timeout'])
            
            if response.status_code == 200:
                data = response.json()
                for record in data.get('data', []):
                    if record['type'] in ['A', 'AAAA']:
                        result['ips'].append({
                            'ip': record['value'],
                            'type': record['type'],
                            'subdomain': record.get('subdomain', '')
                        })
        
        except Exception as e:
            print(f"[!] Shodan error: {str(e)}")
        
        self.cache.set(cache_key, result, CONFIG['cache_ttl_passive'])
        return result
    
    def _collect_censys(self, domain: str) -> Dict[str, List]:
        """Query Censys API (requires API key)"""
        if 'censys_id' not in self.api_keys or 'censys_secret' not in self.api_keys:
            return {'ips': []}
        
        cache_key = f"censys_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {'ips': []}
        
        try:
            url = "https://search.censys.io/api/v2/certificates/search"
            auth = (self.api_keys['censys_id'], self.api_keys['censys_secret'])
            params = {'q': f"names: {domain}", 'per_page': 50}
            
            response = requests.get(url, auth=auth, params=params, timeout=CONFIG['api_timeout'])
            
            if response.status_code == 200:
                data = response.json()
                for cert in data.get('results', []):
                    for name in cert.get('names', []):
                        if not name.startswith('*'):
                            try:
                                answers = self.resolver.resolve(name, 'A')
                                for rdata in answers:
                                    result['ips'].append({
                                        'ip': str(rdata),
                                        'hostname': name,
                                        'source': 'censys_cert_san'
                                    })
                            except Exception:
                                pass
        
        except Exception as e:
            print(f"[!] Censys error: {str(e)}")
        
        self.cache.set(cache_key, result, CONFIG['cache_ttl_passive'])
        return result
    
    def _enrich_with_rdap(self, candidates: Dict):
        """Enrich candidate IPs with ASN and RDAP data"""
        total = len(candidates)
        print(f"[*] Enriching {total} candidate IP(s) with RDAP/ASN data...")
        
        for idx, (ip, data) in enumerate(candidates.items(), 1):
            print(f"[*] Processing {idx}/{total}: {ip}...", end='\r')
            
            try:
                # Use ipwhois or RDAP query
                # Simplified version using ip-api.com (free, no key needed)
                response = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,as,asname,org,isp",
                    timeout=10  # Increased timeout from 5 to 10
                )
                
                if response.status_code == 200:
                    rdap = response.json()
                    if rdap.get('status') == 'success':
                        asn_str = rdap.get('as', '')
                        asn = int(asn_str.split()[0].replace('AS', '')) if asn_str else None
                        
                        data['rdap'] = {
                            'asn': asn,
                            'asn_name': rdap.get('asname', ''),
                            'org': rdap.get('org', ''),
                            'isp': rdap.get('isp', '')
                        }
                        
                        # Check if CDN
                        if asn and asn in CDN_ASNS:
                            data['is_cdn'] = True
                            data['cdn_provider'] = CDN_ASNS[asn]
                
                time.sleep(0.15)  # Increased rate limit to avoid timeouts
            
            except requests.exceptions.Timeout:
                print(f"\n[!] RDAP timeout for {ip} (skipping)")
            except Exception as e:
                print(f"\n[!] RDAP error for {ip}: {str(e)}")
        
        print(f"\n[+] RDAP enrichment complete for {total} IP(s)")       
    
    def _merge_candidates(self, candidates: Dict, result: Dict, source: str):
        """Merge results from a source into candidates dictionary"""
        for ip_data in result.get('ips', []):
            ip = ip_data['ip']
            
            # Filter IPs based on version preference
            try:
                ip_obj = ipaddress.ip_address(ip)
                if self.ipv4_only and ip_obj.version != 4:
                    continue  # Skip IPv6 if ipv4_only is True
            except ValueError:
                continue  # Skip invalid IPs
            
            if ip not in candidates:
                candidates[ip] = {
                    'ip': ip,
                    'evidence': [],
                    'sources': set(),
                    'is_cdn': False
                }
            
            candidates[ip]['sources'].add(source)
            
            # Add evidence
            evidence_item = {
                'source': source,
                'data': ip_data,
                'timestamp': ip_data.get('timestamp', datetime.now(timezone.utc).isoformat())
            }
            candidates[ip]['evidence'].append(evidence_item)
    
    def _score_candidates(self, candidates: Dict, domain: str) -> List[Dict]:
        """Score each candidate IP based on evidence"""
        scored = []
        
        print(f"\n[*] Scoring {len(candidates)} candidate IP(s)...")
        
        for ip, data in candidates.items():
            score = 0
            reasons = []
            signal_count = 0
            
            # Check for direct origin subdomain
            for evidence in data['evidence']:
                if evidence['data'].get('is_origin_subdomain'):
                    score += SCORE_WEIGHTS['direct_origin_record']
                    reasons.append('Direct origin subdomain record')
                    signal_count += 1
                    break
            
            # Recent passive DNS
            recent_count = 0
            cutoff = datetime.now(timezone.utc) - timedelta(hours=CONFIG['temporal_freshness_hours'])
            
            for evidence in data['evidence']:
                ts_str = evidence.get('timestamp', '')
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                        if ts > cutoff:
                            recent_count += 1
                    except Exception:
                        pass
            
            if recent_count > 0:
                score += SCORE_WEIGHTS['recent_passive_dns']
                reasons.append(f'Recent DNS records ({recent_count})')
                signal_count += 1
            
            # Certificate SAN match
            if 'ct_logs' in data['sources']:
                score += SCORE_WEIGHTS['cert_san_match']
                reasons.append('Certificate SAN contains domain')
                signal_count += 1
            
            # Multiple independent sources
            if len(data['sources']) >= CONFIG['min_independent_signals']:
                reasons.append(f"Multiple sources ({len(data['sources'])})")
                signal_count += 1
            
            # ASN check
            if 'rdap' in data:
                if not data.get('is_cdn'):
                    score += SCORE_WEIGHTS['non_cdn_asn']
                    reasons.append(f"Non-CDN ASN: {data['rdap'].get('asn_name', 'Unknown')}")
                    signal_count += 1
                else:
                    score += SCORE_WEIGHTS['cdn_penalty']
                    reasons.append(f"CDN detected: {data.get('cdn_provider', 'Unknown')}")
            
            # Shodan/Censys presence
            if 'shodan' in data['sources'] or 'censys' in data['sources']:
                score += SCORE_WEIGHTS['shodan_match']
                reasons.append('Found in threat intel indexes')
                signal_count += 1
            
            # Normalize score to 0-100
            normalized_score = max(0, min(100, score))
            
            # Determine tags
            tags = []
            if normalized_score >= CONFIG['high_confidence_threshold']:
                tags.append('high-confidence')
            elif normalized_score >= CONFIG['confidence_threshold']:
                tags.append('probable-origin')
            else:
                tags.append('low-confidence')
            
            if data.get('is_cdn'):
                tags.append('cdn-ip')
            else:
                tags.append('non-cdn')
            
            if signal_count >= CONFIG['min_independent_signals']:
                tags.append('multi-source')
            
            result = {
                'ip': ip,
                'score': normalized_score,
                'signal_count': signal_count,
                'evidence': data['evidence'],
                'sources': list(data['sources']),
                'rdap': data.get('rdap', {}),
                'is_cdn': data.get('is_cdn', False),
                'cdn_provider': data.get('cdn_provider', ''),
                'tags': tags,
                'reasons': reasons,
                'notes': self._generate_notes(normalized_score, signal_count, data)
            }
            
            scored.append(result)
            
            # 🎯 REAL-TIME OUTPUT: Print high-confidence IPs immediately
            if normalized_score >= CONFIG['confidence_threshold']:
                print(f"\n{'='*80}")
                print(f"🎯 POTENTIAL ORIGIN IP FOUND!")
                print(f"{'='*80}")
                print(f"IP: {ip}")
                print(f"Score: {normalized_score}/100")
                print(f"Tags: {', '.join(tags)}")
                if result['rdap']:
                    print(f"ASN: AS{result['rdap'].get('asn', 'N/A')} - {result['rdap'].get('asn_name', 'Unknown')}")
                print(f"Notes: {result['notes']}")
                print(f"{'='*80}\n")
        
        return scored
    
    def _generate_notes(self, score: int, signals: int, data: Dict) -> str:
        """Generate human-readable notes for the IP"""
        if score >= CONFIG['high_confidence_threshold']:
            return f"High confidence — {signals} independent signals, likely origin IP"
        elif score >= CONFIG['confidence_threshold']:
            return f"Probable origin — {signals} signals but requires verification"
        elif data.get('is_cdn'):
            return f"Low confidence — IP belongs to {data.get('cdn_provider', 'CDN')}"
        else:
            return f"Insufficient evidence — only {signals} signals found"

    def _install_playwright_chromium(self) -> bool:
        """Install Playwright Chromium browser binary using the active Python executable."""
        print("[*] Playwright browser binary missing. Installing Chromium...")
        try:
            subprocess.run(
                [sys.executable, '-m', 'playwright', 'install', 'chromium'],
                check=True,
            )
            print("[+] Playwright Chromium installation complete")
            return True
        except Exception as e:
            print(f"[!] Failed to install Playwright Chromium: {str(e)}")
            print(f"[!] Try manually: {sys.executable} -m playwright install chromium")
            return False

    def _launch_browser_with_fallback(self, playwright):
        """Launch Chromium and auto-install browser binaries if needed."""
        try:
            return playwright.chromium.launch(headless=True)
        except PlaywrightError as e:
            msg = str(e)
            if 'Executable doesn\'t exist' in msg or 'Please run the following command to download new browsers' in msg:
                if self._install_playwright_chromium():
                    return playwright.chromium.launch(headless=True)
            raise
    
    def take_screenshots(self, results: List[Dict], domain: str, output_dir: str = 'screenshots', max_parallel: int = 5) -> Dict[str, str]:
        """
        Take full-page screenshots of each IP address with optimized batching
        Returns a dict mapping IP to screenshot filename
        
        Args:
            results: List of IP results
            domain: Target domain name
            output_dir: Directory to save screenshots
            max_parallel: Maximum number of parallel pages per batch (default: 5)
        """
        # Create output directory
        screenshots_dir = Path(output_dir) / domain.replace('.', '_')
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        
        screenshot_map = {}
        total = len(results)
        completed = 0
        
        print(f"\n[*] Taking screenshots for {total} IP(s) with batched processing...")
        print(f"[*] Screenshots will be saved to: {screenshots_dir}")
        print(f"[*] Processing in batches of {max_parallel} for optimal speed")
        
        with sync_playwright() as p:
            # Launch browser once
            browser = self._launch_browser_with_fallback(p)
            
            # Process in batches for speed
            for batch_start in range(0, total, max_parallel):
                batch_end = min(batch_start + max_parallel, total)
                batch = results[batch_start:batch_end]
                pages = []
                
                # Open all pages in the batch
                for result in batch:
                    try:
                        page = browser.new_page(
                            viewport={'width': 1920, 'height': 1080},
                            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                            ignore_https_errors=True
                        )
                        pages.append((result['ip'], result['score'], page))
                    except Exception as e:
                        print(f"[!] Failed to create page for {result['ip']}: {str(e)[:50]}")
                
                # Navigate all pages simultaneously
                for ip, score, page in pages:
                    protocols = ['https', 'http']
                    screenshot_taken = False
                    
                    for protocol in protocols:
                        if screenshot_taken:
                            break
                        
                        url = f"{protocol}://{ip}"
                        try:
                            # Quick navigate
                            page.goto(url, wait_until='domcontentloaded', timeout=8000)
                            page.wait_for_timeout(800)  # Brief wait for content
                            
                            # Generate filename
                            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')[:19]
                            safe_ip = ip.replace(':', '_')
                            filename = f"{safe_ip}_score{score}_{protocol}_{timestamp}.png"
                            filepath = screenshots_dir / filename
                            
                            # Take screenshot
                            page.screenshot(path=str(filepath), full_page=True)
                            screenshot_map[ip] = str(filepath)
                            screenshot_taken = True
                            completed += 1
                            print(f"[+] {completed}/{total}: {ip} ({protocol})")
                            
                        except Exception:
                            # Try next protocol
                            pass
                    
                    if not screenshot_taken:
                        completed += 1
                        print(f"[!] {completed}/{total}: Could not capture {ip}")
                
                # Close all pages in batch
                for _, _, page in pages:
                    try:
                        page.close()
                    except Exception:
                        pass
            
            browser.close()
        
        print(f"\n[+] Screenshot capture complete: {len(screenshot_map)}/{total} successful")
        return screenshot_map
    
    def close(self):
        """Cleanup resources"""
        self.cache.close()


def main():
    parser = argparse.ArgumentParser(
        description='Multi-source origin IP discovery tool',
        epilog='API keys are loaded from environment variables (.env supported). Legacy config file is optional via --config.'
    )
    parser.add_argument('domain', help='Target domain to investigate')
    parser.add_argument('--config', '-c', default='config.yaml',
                       help='Optional legacy config file path (default: config.yaml)')
    parser.add_argument('--min-score', type=int, default=50,
                       help='Minimum confidence score to display (default: 50)')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed evidence')
    parser.add_argument('--ipv6', action='store_true',
                       help='Include IPv6 addresses (default: IPv4 only)')
    parser.add_argument('--screenshot', '-s', action='store_true',
                       help='Take full-page screenshots of all discovered IPs')
    parser.add_argument('--screenshot-dir', default='screenshots',
                       help='Directory to save screenshots (default: screenshots)')
    parser.add_argument('--screenshot-parallel', type=int, default=5,
                       help='Number of parallel screenshot captures (default: 5)')
    parser.add_argument('--verify', action='store_true',
                       help='Verify candidates by comparing response content (Levenshtein distance)')
    parser.add_argument('--levenshtein-threshold', type=float, default=0.85,
                       help='Content similarity threshold for verification (0-1, default: 0.85)')
    parser.add_argument('-help', action='help',
                       help='Show this help message and exit')
    
    args = parser.parse_args()
    
    # Load API keys from config file
    api_keys = load_api_keys(args.config)
    
    # Run discovery
    ipv4_only = not args.ipv6
    finder = OriginIPFinder(api_keys, ipv4_only=ipv4_only)
    
    if ipv4_only:
        print("[*] IPv4 only mode (use --ipv6 to include IPv6 addresses)")
    else:
        print("[*] Including both IPv4 and IPv6 addresses")
    
    try:
        results = finder.find_origin_ips(args.domain)
        
        # Filter by minimum score
        filtered = [r for r in results if r['score'] >= args.min_score]
        
        print(f"\n{'='*80}")
        print(f"Origin IP Discovery Results for: {args.domain}")
        print(f"{'='*80}\n")
        
        if not filtered:
            print(f"[!] No candidates found with score >= {args.min_score}")
        else:
            for result in filtered:
                print(f"IP: {result['ip']}")
                print(f"Score: {result['score']}/100")
                print(f"Tags: {', '.join(result['tags'])}")
                print(f"Sources: {', '.join(result['sources'])}")
                
                if result['rdap']:
                    print(f"ASN: AS{result['rdap'].get('asn', 'N/A')} - {result['rdap'].get('asn_name', 'Unknown')}")
                    print(f"ISP: {result['rdap'].get('isp', 'Unknown')}")
                
                print(f"Notes: {result['notes']}")
                print(f"Reasons: {'; '.join(result['reasons'])}")
                
                if args.verbose:
                    print("\nEvidence:")
                    for evidence in result['evidence'][:5]:  # Show first 5
                        print(f"  - {evidence['source']}: {evidence['timestamp']}")
                
                print(f"{'-'*80}\n")
        
        # Verify candidates if requested
        verification_map = {}
        if args.verify:
            CONFIG['levenshtein_threshold'] = args.levenshtein_threshold
            # Construct original URL - try all results to find a working one
            original_url = f"https://{args.domain}/"
            verification_map = finder.verifier.verify_all_candidates(results, original_url)
            
            # Add verification data to results
            for result in results:
                if result['ip'] in verification_map:
                    result['verification'] = verification_map[result['ip']]
        
        # Take screenshots if requested
        screenshot_map = {}
        if args.screenshot:
            screenshot_map = finder.take_screenshots(
                results, 
                args.domain, 
                args.screenshot_dir,
                args.screenshot_parallel
            )
        
        # Always save to JSON file with timestamp
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        
        # Categorize results by confidence level
        high_conf = [r for r in results if r['score'] >= CONFIG['high_confidence_threshold']]
        probable = [r for r in results if CONFIG['confidence_threshold'] <= r['score'] < CONFIG['high_confidence_threshold']]
        low_conf = [r for r in results if r['score'] < CONFIG['confidence_threshold']]
        
        # Add screenshot paths to results
        for result in results:
            if result['ip'] in screenshot_map:
                result['screenshot'] = screenshot_map[result['ip']]
            
            # Simplify evidence data for readability
            result['evidence_summary'] = {
                'sources': result['sources'],
                'total_evidence_count': len(result['evidence']),
                'evidence_types': list(set([e['source'] for e in result['evidence']]))
            }
            # Keep full evidence in separate field
            result['detailed_evidence'] = result.pop('evidence')
        
        # Prepare readable output structure
        output_data = {
            'scan_metadata': {
                'domain': args.domain,
                'scan_time': datetime.now(timezone.utc).isoformat(),
                'scan_date': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                'ipv4_only': not args.ipv6,
                'screenshots_enabled': args.screenshot,
                'screenshots_taken': len(screenshot_map),
                'verification_enabled': args.verify,
                'levenshtein_threshold': args.levenshtein_threshold if args.verify else None
            },
            'summary': {
                'total_candidates': len(results),
                'high_confidence_count': len(high_conf),
                'probable_origin_count': len(probable),
                'low_confidence_count': len(low_conf),
                'verified_count': len([v for v in verification_map.values() if v['verified']]) if verification_map else 0,
                'scoring_thresholds': {
                    'high_confidence': CONFIG['high_confidence_threshold'],
                    'probable_origin': CONFIG['confidence_threshold']
                }
            },
            'high_confidence_ips': high_conf,
            'probable_origin_ips': probable,
            'low_confidence_ips': low_conf,
            'scoring_explanation': {
                'weights': SCORE_WEIGHTS,
                'description': 'Each IP is scored based on multiple signals. Higher scores indicate more confidence that this is an origin IP.'
            },
            'verification_explanation': {
                'enabled': args.verify,
                'method': 'Content verification using Levenshtein distance similarity' if args.verify else None,
                'threshold': args.levenshtein_threshold if args.verify else None,
                'description': 'Verified IPs match original content with similarity >= threshold or matching HTTP headers. Unverified IPs may still be origin if passive intel is strong.' if args.verify else None
            }
        }
        
        # Determine output filename and ensure JSON files are organized in json/<target>/
        domain_slug = args.domain.replace('.', '_')
        json_dir = Path('json') / domain_slug
        json_dir.mkdir(parents=True, exist_ok=True)

        if args.output:
            output_path = Path(args.output)
            if output_path.is_absolute():
                output_file = output_path
            elif output_path.parent == Path('.'):
                output_file = json_dir / output_path
            else:
                output_file = output_path
        else:
            output_file = json_dir / f"{domain_slug}_{timestamp}.json"

        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Save to JSON with better formatting
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] Complete results saved to: {output_file}")
        summary_str = f"[+] Summary: {output_data['summary']['high_confidence_count']} high-confidence, " \
                      f"{output_data['summary']['probable_origin_count']} probable, " \
                      f"{output_data['summary']['low_confidence_count']} low-confidence IPs"
        if output_data['summary']['verified_count']:
            summary_str += f", {output_data['summary']['verified_count']} VERIFIED"
        print(summary_str)
    
    finally:
        finder.close()


if __name__ == '__main__':
    main()