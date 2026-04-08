# Origin IP Finder

Origin IP Finder is a professional, multi-source reconnaissance and verification tool designed to identify likely origin hosts behind reverse proxies and CDN layers.

It combines passive intelligence, confidence scoring, active response verification, and visual capture into one workflow to produce reliable and actionable results.

## Core Features

- Multi-source candidate discovery from DNS, CT logs, Shodan, Censys, and RDAP/ASN enrichment
- Weighted confidence scoring with clear reason output
- Optional active verification using response similarity and header fingerprinting
- Automated full-page screenshot capture for discovered candidates
- Parallel processing for discovery, verification, and screenshot steps
- Structured JSON output stored by target for clean project organization
- Automatic Playwright browser install fallback for screenshot mode

## How It Works

1. Collect candidate IPs from multiple intelligence sources.
2. Enrich each candidate with ASN and provider context.
3. Score candidates using weighted evidence and confidence thresholds.
4. Optionally verify content similarity against the target host.
5. Optionally capture full-page screenshots of candidate endpoints.
6. Save structured results to the JSON output directory.

## Requirements

- Python 3.9+
- Internet access

## Installation

1. Install dependencies:

```powershell
pip install dnspython requests playwright
```

2. Install browser engine for screenshots:

```powershell
python -m playwright install chromium
```

## Configuration

This repository includes a tracked config.yaml with empty keys so users can clone, edit, and start quickly.

Edit config.yaml and paste your credentials:

```yaml
shodan_api_key: ""
censys_api_id: ""
censys_api_secret: ""
dnsdb_api_key: ""
passivetotal_api_key: ""
securitytrails_api_key: ""
```

Notes:
- Leave fields empty to run with free/public sources only.
- Environment variables and .env are also supported for private setups.

## Quick Start

Basic scan:

```powershell
python origin_finder.py example.com
```

Scan with screenshots:

```powershell
python origin_finder.py example.com --screenshot
```

Scan with active verification:

```powershell
python origin_finder.py example.com --verify
```

Full workflow:

```powershell
python origin_finder.py example.com --verify --screenshot --screenshot-parallel 5 --verbose
```

## Command Options

- domain: Target domain to investigate
- --config, -c: Config file path
- --min-score: Minimum score to print in terminal output
- --output, -o: Custom output JSON file path
- --verbose, -v: Print detailed evidence in terminal
- --ipv6: Include IPv6 candidates
- --screenshot, -s: Capture screenshots for candidates
- --screenshot-dir: Screenshot base directory
- --screenshot-parallel: Screenshot concurrency value
- --verify: Enable active response verification
- --levenshtein-threshold: Similarity threshold for verification
- -h, --help, -help: Show command help

## Output Structure

JSON results are saved under:

- json/target_domain_slug/target_domain_slug_YYYYMMDD_HHMMSS.json

Screenshots are saved under:

- screenshots/target_domain_slug/

Each JSON report contains:

- scan_metadata
- summary
- high_confidence_ips
- probable_origin_ips
- low_confidence_ips
- scoring_explanation
- verification_explanation

## Confidence Model

The scoring pipeline weighs multiple independent signals, including:

- Direct origin-style DNS records
- Recency of DNS evidence
- Certificate SAN correlation
- ASN context and CDN penalty handling
- Threat intel presence (Shodan/Censys)

Default confidence bands:

- High confidence: score >= 85
- Probable origin: score >= 75 and < 85
- Low confidence: score < 75

## Professional Usage Guidance

- Start with default scoring and verification enabled for high signal quality.
- Use screenshots for fast visual triage and reporting.
- Use verbose mode when you need evidence-level transparency.
- Keep API credentials private and rotate them regularly.

## Security and Repository Hygiene

- config.yaml is intentionally tracked with empty values for onboarding.
- Local secrets in .env are ignored by git.
- Runtime artifacts (json output, screenshots, local DB) are ignored by git.

## Legal and Responsible Use

Use this tool only on systems you own or have explicit authorization to assess.
