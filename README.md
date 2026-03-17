<div align="center">

# 🎯 scope_checker

**Never waste time on out-of-scope targets again.**

[![Python 3.8+](<https://img.shields.io/badge/python-3.8%2B-blue.svg>)](<https://www.python.org/downloads/>)
[![License: MIT](<https://img.shields.io/badge/License-MIT-green.svg>)](LICENSE)
[![Version](<https://img.shields.io/badge/version-2.1.0-orange.svg>)](CHANGELOG.md)

A production-grade bug bounty scope validator that prevents you from accidentally
testing out-of-scope targets — saving time, avoiding trouble, and keeping your
workflow clean.

[Installation](#installation) •
[Quick Start](#quick-start) •
[Usage](#usage) •
[Pipe Integration](#pipe-integration) •
[API Import](#api-import) •
[Configuration](#configuration) •
[FAQ](#faq)

</div>

---

## The Problem

You're running recon. Subfinder spits out 2,000 subdomains. Nuclei starts
scanning. Three hours later you realize half your targets were out of scope.
Worse — you've been hammering a domain that's explicitly excluded, and now the
program has flagged your account.

**scope_checker** sits between your tools and your targets. It validates
everything against the program's scope definition before a single packet leaves
your machine.
```

subfinder -d [target.com](http://target.com/) | scope_checker --filter -p shopify | nuclei -t cves/
↑
only in-scope targets pass through

```

---

## Features

| Feature | Description |
|---|---|
| **5 Import Formats** | HackerOne API, Bugcrowd API, YAML, JSON, plain text |
| **Smart Matching** | Wildcards, CIDRs, IP ranges, URL paths, port ranges |
| **Exclusion Priority** | `admin.example.com` stays excluded even when `*.example.com` is in scope |
| **IPv4 + IPv6** | Full support including CIDR notation for both |
| **Wildcard Strict Mode** | `*.example.com` can optionally exclude the apex `example.com` |
| **Pipe-Friendly** | Filter stdin/stdout — integrates with any recon tool |
| **Scope Diffing** | See exactly what changed when you re-import scope |
| **Local Database** | SQLite storage with WAL mode, migrations, auto-backup |
| **Secure Credentials** | Config file with `0600` permissions — tokens never leak to `ps aux` |
| **Bounty Tracking** | Shows 💰 for bounty-eligible assets |
| **Staleness Warnings** | Alerts when scope data is >30 days old |
| **127 Built-in Tests** | Run `--self-test` to verify everything works on your system |
| **Zero Dependencies** | Core functionality works with stdlib only. `requests`/`pyyaml` optional |

---

## Installation

### One-Line Install

```bash
curl -sL <https://raw.githubusercontent.com/youruser/scope_checker/main/scope_checker.py> -o scope_checker.py && chmod +x scope_checker.py
```

### Clone & Setup

```bash
git clone <https://github.com/youruser/scope_checker.git>
cd scope_checker
pip install -r requirements.txt   # optional: requests, pyyaml
python scope_checker.py --self-test
```

### Requirements

```
# requirements.txt
requests>=2.31.0    # only needed for HackerOne/Bugcrowd API import
pyyaml>=6.0.1       # only needed for YAML import/export
```

**Python 3.8+** required. Core functionality (domain/IP/URL/port matching,
SQLite database, text/JSON parsing, pipe filtering) works with **zero
external dependencies**.

### Optional: Add to PATH

```bash
# Linux/macOS
sudo cp scope_checker.py /usr/local/bin/scope_checker
sudo chmod +x /usr/local/bin/scope_checker

# Or symlink
ln -s $(pwd)/scope_checker.py ~/.local/bin/scope_checker
```

### Verify Installation

```bash
python scope_checker.py --self-test

# Expected output:
# ══════════ SCOPE CHECKER v2.1 SELF-TEST ══════════
# ✓ ALL 127 TESTS PASSED
```

---

## Quick Start

### 1. Create a Scope File

```bash
python scope_checker.py --init my-program.yaml
```

This generates a sample YAML file:

```yaml
program: my-program
platform: custom

in_scope:
  - "*.example.com"
  - asset: api.example.com
    eligible_for_bounty: true
    max_severity: critical
    instruction: "All API endpoints"
  - asset: "10.0.0.0/24"
  - asset: "2001:db8::/32"

out_of_scope:
  - admin.example.com
  - asset: "*.staging.example.com"
    reason: "Test environment — no bounties"
  - asset: "<https://example.com/health>"
    reason: "Health check endpoint"

ports:
  - 80
  - 443
  - 8080-8090
```

### 2. Import It

```bash
python scope_checker.py --import-yaml my-program.yaml
```

### 3. Check Targets

```bash
# Single target
python scope_checker.py -p my-program -c dev.example.com
# [IN SCOPE] dev.example.com 💰

python scope_checker.py -p my-program -c admin.example.com
# [OUT OF SCOPE] admin.example.com

# Verbose mode
python scope_checker.py -p my-program -c dev.example.com -v
# [IN SCOPE] dev.example.com 💰
#   Rule:   *.example.com
#   Type:   wildcard_match
#   Reason: Matched wildcard: *.example.com
```

### 4. Filter Tool Output

```bash
subfinder -d example.com | python scope_checker.py --filter -p my-program
# Only in-scope subdomains are printed
```

---

## Usage

### Command Reference

```
scope_checker.py [OPTIONS]

Import:
  --import-scope {hackerone,bugcrowd}  Fetch scope from platform API
  --import-yaml FILE                   Import from YAML file
  --import-json FILE                   Import from JSON file
  --import-txt FILE                    Import from plain text file

Manage:
  -p, --program NAME          Program name (required for most operations)
  --add-in ASSET              Add an in-scope asset
  --add-out ASSET             Add an out-of-scope asset
  --remove-asset ASSET        Remove an asset
  --delete-program            Delete entire program from database
  --wildcard-strict           *.x.com does NOT match x.com itself
  --update                    Re-fetch scope from original API

Check:
  -c, --check TARGET          Check any target (auto-detects type)
  --check-ip IP               Check an IP address
  --check-url URL             Check a URL
  --check-port PORT           Check a port number
  --check-file FILE           Check all targets in a file

Filter (pipe-friendly):
  -f, --filter                stdin → stdout, only in-scope targets
  --filter-out                stdin → stdout, only OUT-of-scope targets

Display:
  -s, --show-scope            Display program scope
  -l, --list-programs         List all stored programs
  --search QUERY              Search programs by name
  --stats                     Show database statistics
  --diff                      Show scope changes on import
  -v, --verbose               Verbose output with match details
  --json-output               Output in JSON format
  -q, --quiet                 Exit code only (0=in-scope, 1=out)
  --version                   Show version

Export:
  --export-yaml FILE          Export scope to YAML
  --export-json FILE          Export scope to JSON
  --export-txt FILE           Export in-scope assets to plain text

Setup:
  --self-test                 Run 127 built-in tests
  --config                    Configure API credentials securely
  --init FILE                 Create sample scope YAML file
  --backup                    Manually backup database
```

---

## Scope Definition Formats

### YAML (Recommended)

```yaml
program: shopify
platform: hackerone

in_scope:
  # Simple string format
  - "*.myshopify.com"
  - "*.shopify.com"

  # Detailed format with metadata
  - asset: "*.shopifycloud.com"
    eligible_for_bounty: true
    max_severity: critical
    instruction: "All cloud infrastructure"

  - asset: api.shopify.com
    eligible_for_bounty: true
    max_severity: high

out_of_scope:
  - "*.shopifyapps.com"
  - asset: admin.shopify.com
    reason: "Internal admin panel"
  - asset: "<https://shopify.com/careers>"
    reason: "Marketing pages"

# Optional: IP ranges
ip_ranges:
  - "10.0.0.0/8"
  - range: "172.16.0.0/12"
    exclude: true

# Optional: Port restrictions
ports:
  - 80
  - 443
  - 8080-8090
```

### JSON

```json
{
  "program": "shopify",
  "platform": "custom",
  "in_scope": [
    "*.myshopify.com",
    {
      "asset": "*.shopify.com",
      "eligible_for_bounty": true,
      "instruction": "Main domain"
    }
  ],
  "out_of_scope": [
    "admin.shopify.com",
    {
      "asset": "*.staging.shopify.com",
      "instruction": "Staging environment"
    }
  ]
}
```

### Plain Text

```
# My Program Scope
# Lines starting with # are comments

in-scope:
*.example.com
api.example.com
192.168.0.0/16
2001:db8::/32

out-of-scope:
admin.example.com
staging.example.com
*.test.example.com
```

**Section markers recognized:** `in-scope:`, `in_scope:`, `[in-scope]`,
`## In Scope`, `out-of-scope:`, `out_of_scope:`, `[out-of-scope]`,
`## Out of Scope`, `exclusions:`

---

## Pipe Integration

scope_checker is designed to sit in your recon pipeline:

### Filter Subdomains

```bash
# Only in-scope subdomains
subfinder -d example.com | scope_checker --filter -p myprogram

# Only in-scope, then scan
subfinder -d example.com | scope_checker --filter -p myprogram | httpx

# Full pipeline
subfinder -d example.com \\
  | scope_checker --filter -p myprogram \\
  | httpx -silent \\
  | nuclei -t cves/
```

### Filter IPs

```bash
# Masscan results through scope checker
masscan -p80,443 10.0.0.0/8 --rate 10000 -oL - \\
  | awk '{print $4}' \\
  | scope_checker --filter -p myprogram
```

### Show Out-of-Scope (debugging)

```bash
# What am I missing?
subfinder -d example.com | scope_checker --filter-out -p myprogram
```

### JSON Pipeline

```bash
# JSON output for automation
subfinder -d example.com \\
  | scope_checker --filter -p myprogram --json-output \\
  | jq -r '.target'
```

### Bulk File Check

```bash
# Check a file of targets
cat recon/all-subdomains.txt | scope_checker --filter -p myprogram > recon/in-scope.txt

# Or use --check-file for detailed results
scope_checker -p myprogram --check-file recon/all-subdomains.txt
```

### Exit Code Integration

```bash
# Use in scripts with exit codes
if scope_checker -p myprogram -c "$target" --quiet; then
    echo "Proceeding with $target"
    nuclei -u "$target" -t cves/
else
    echo "Skipping $target (out of scope)"
fi
```

### Bash Function Wrapper

```bash
# Add to ~/.bashrc or ~/.zshrc
inscope() {
    scope_checker --filter -p "${1:-default}"
}

# Usage
subfinder -d example.com | inscope myprogram | httpx
```

---

## API Import

### HackerOne

```bash
# 1. Configure credentials (once)
scope_checker --config
# Enter your HackerOne API username and token

# 2. Import
scope_checker --import-scope hackerone -p shopify

# 3. Refresh later
scope_checker -p shopify --update
```

**Getting HackerOne API credentials:**

1. Go to https://hackerone.com/settings/api_token/edit
2. Generate an API token
3. Your username is your HackerOne handle

### Bugcrowd

```bash
# 1. Configure
scope_checker --config
# Enter your Bugcrowd API token

# 2. Import
scope_checker --import-scope bugcrowd -p tesla
```

### Environment Variables (Alternative)

```bash
# HackerOne
export HACKERONE_API_USER="your_username"
export HACKERONE_API_TOKEN="your_token"

# Bugcrowd
export BUGCROWD_API_TOKEN="your_token"
```

> **Security Note:** `--config` stores credentials in
`~/.scope_checker/config.yaml` with `0600` permissions. This is safer than
passing tokens via `--api-token` which exposes them in `ps aux`.
> 

---

## Configuration

### File Locations

```
~/.scope_checker
├── config.yaml         # API credentials (0600 permissions)
├── scope_checker.log   # Debug log (when -v is used)
└── backups/            # Auto-backups before destructive operations
    ├── scopes_20240115_143022.db
    └── scopes_20240116_091544.db
```

### Database Management

```bash
# List all programs
scope_checker --list-programs

# Search programs
scope_checker --search shopify

# Database stats
scope_checker --stats

# Manual backup
scope_checker --backup

# Delete a program (auto-backs up first)
scope_checker -p old-program --delete-program
```

### Export / Migration

```bash
# Export to YAML (for version control)
scope_checker -p myprogram --export-yaml scope-backup.yaml

# Export to JSON (for automation)
scope_checker -p myprogram --export-json scope.json

# Export just the in-scope assets (for tool input)
scope_checker -p myprogram --export-txt inscope-targets.txt

# Re-import on another machine
scope_checker --import-yaml scope-backup.yaml
```

---

## Matching Rules

### Priority Order

Exclusions are **always checked first**. This prevents false positives:

```
1. Exact exclusion      (admin.example.com → OUT)
2. Wildcard exclusion   (*.staging.example.com → OUT)
3. Exact inclusion      (specific.target.com → IN)
4. Wildcard inclusion   (*.example.com → IN)
5. No match             → OUT
```

### Domain Matching

| Scope Rule | Target | Result | Why |
| --- | --- | --- | --- |
| `*.example.com` | `dev.example.com` | ✅ IN | Wildcard match |
| `*.example.com` | `a.b.c.example.com` | ✅ IN | Deep subdomain matches |
| `*.example.com` | `example.com` | ✅ IN | Apex matches (default) |
| `*.example.com` + `--wildcard-strict` | `example.com` | ❌ OUT | Strict: apex excluded |
| `*.example.com` + exclude `admin.example.com` | `admin.example.com` | ❌ OUT | Exclusion wins |
| `*.example.com` + exclude `*.staging.example.com` | `test.staging.example.com` | ❌ OUT | Wildcard exclusion wins |

### IP Matching

| Scope Rule | Target | Result |
| --- | --- | --- |
| `192.168.1.0/24` | `192.168.1.50` | ✅ IN |
| `192.168.1.0/24` + exclude `192.168.1.1` | `192.168.1.1` | ❌ OUT |
| `10.0.0.50-10.0.0.100` | `10.0.0.75` | ✅ IN |
| `10.0.0.50-10.0.0.100` | `10.0.0.101` | ❌ OUT |
| `2001:db8::/32` | `2001:db8::1` | ✅ IN |

### URL Matching

| Scope Rule | Target | Result |
| --- | --- | --- |
| `*.example.com` | `https://dev.example.com/api` | ✅ IN |
| exclude `https://example.com/v1/health` | `https://example.com/v1/health` | ❌ OUT |
| exclude `https://example.com/v1/health` | `https://example.com/v1/users` | ✅ IN |
| ports `80,443` | `https://dev.example.com:9999/api` | ❌ OUT |

### Port Matching

| Scope Rule | Target | Result |
| --- | --- | --- |
| `443` | `443` | ✅ IN |
| `8080-8090` | `8085` | ✅ IN |
| `8080-8090` | `8091` | ❌ OUT |
| (no port rules) | any port | ✅ IN |

### Wildcard Strict Mode

Some programs define `*.example.com` to mean **only subdomains**, not the apex
domain itself. Use `--wildcard-strict` for this behavior:

```bash
# Enable for a program (persisted in DB)
scope_checker -p myprogram --wildcard-strict

# Or per-command
scope_checker -p myprogram -c example.com --wildcard-strict
# [OUT OF SCOPE] example.com

scope_checker -p myprogram -c sub.example.com --wildcard-strict
# [IN SCOPE] sub.example.com
```

---

## Scope Diffing

When you re-import scope, scope_checker shows exactly what changed:

```bash
$ scope_checker --import-yaml updated-scope.yaml

✓ Imported myprogram
  In: 15  Out: 8

  3 change(s) detected:

  + [IN]  new-api.example.com (domain)
  - [IN]  old-api.example.com (domain)
  + [OUT] *.legacy.example.com (wildcard)
```

This prevents surprises when programs silently update their scope.

---

## Workflow Examples

### Bug Bounty Recon Pipeline

```bash
#!/bin/bash
PROGRAM="shopify"

# 1. Import scope
scope_checker --import-scope hackerone -p $PROGRAM

# 2. Subdomain enumeration → filter → probe
subfinder -d shopify.com -all -silent \\
  | scope_checker --filter -p $PROGRAM \\
  | httpx -silent -o alive.txt

# 3. Scan only in-scope, alive hosts
nuclei -l alive.txt -t cves/ -o vulns.txt
```

### Multi-Program Management

```bash
# Import multiple programs
scope_checker --import-yaml scopes/shopify.yaml
scope_checker --import-yaml scopes/google.yaml
scope_checker --import-yaml scopes/meta.yaml

# List them
scope_checker --list-programs

# Program         Platform     In  Out  Updated
# ──────────────────────────────────────────────
# shopify          hackerone    12    5  2024-01-15T14:30:22
# google           custom       8    3  2024-01-14T09:15:00
# meta             custom      15    7  2024-01-13T11:22:33

# Check against specific program
scope_checker -p google -c test.google.com
```

### CI/CD Scope Validation

```bash
#!/bin/bash
# validate-scope.sh — run before any scanning job
set -e

TARGETS_FILE="$1"
PROGRAM="$2"

# Check all targets, fail if any are out of scope
RESULT=$(scope_checker -p "$PROGRAM" --check-file "$TARGETS_FILE" --json-output)
OUT_COUNT=$(echo "$RESULT" | jq '.summary.out_of_scope')

if [ "$OUT_COUNT" -gt 0 ]; then
    echo "ERROR: $OUT_COUNT targets are out of scope!"
    echo "$RESULT" | jq '.results[] | select(.in_scope == false) | .target'
    exit 1
fi

echo "All targets validated as in-scope."
```

### Quick Scope Check Script

```bash
# Add to ~/.bashrc
scopecheck() {
    local program="${1:?Usage: scopecheck <program> <target>}"
    local target="${2:?Usage: scopecheck <program> <target>}"
    scope_checker -p "$program" -c "$target" -v
}

# Usage
scopecheck shopify dev.myshopify.com
```

---

## JSON Output

All commands support `--json-output` for automation:

### Check Result

```bash
$ scope_checker -p myprogram -c dev.example.com --json-output
```

```json
{
  "target": "dev.example.com",
  "in_scope": true,
  "matched_rule": "*.example.com",
  "match_type": "wildcard_match",
  "reason": "Matched wildcard: *.example.com",
  "eligible_for_bounty": true
}
```

### Batch Check

```bash
$ scope_checker -p myprogram --check-file targets.txt --json-output
```

```json
{
  "results": [
    {
      "target": "dev.example.com",
      "in_scope": true,
      "matched_rule": "*.example.com",
      "match_type": "wildcard_match",
      "reason": "Matched wildcard: *.example.com",
      "eligible_for_bounty": true
    },
    {
      "target": "admin.example.com",
      "in_scope": false,
      "matched_rule": "admin.example.com",
      "match_type": "exact_exclusion",
      "reason": "Explicitly excluded: admin.example.com",
      "eligible_for_bounty": false
    }
  ],
  "summary": {
    "in": 1,
    "out": 1
  }
}
```

### Filter Mode

```bash
$ echo -e "dev.example.com\\nadmin.example.com" | scope_checker --filter -p myprogram --json-output
```

```json
{"target": "dev.example.com", "in_scope": true, "rule": "*.example.com"}
```

### Scope Display

```bash
$ scope_checker -p myprogram --show-scope --json-output
```

```json
{
  "program": "myprogram",
  "platform": "custom",
  "is_stale": false,
  "in_scope": [
    {
      "asset": "*.example.com",
      "asset_type": "wildcard",
      "scope_type": "in",
      "instruction": "",
      "eligible_for_bounty": true,
      "max_severity": "critical"
    }
  ],
  "out_of_scope": [
    {
      "asset": "admin.example.com",
      "asset_type": "domain",
      "scope_type": "out",
      "instruction": "Internal admin panel",
      "eligible_for_bounty": false,
      "max_severity": "critical"
    }
  ]
}
```

---

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Target is **in scope** (or command succeeded) |
| `1` | Target is **out of scope** (or command failed) |
| `130` | Interrupted (Ctrl+C) |

Use in scripts:

```bash
scope_checker -p prog -c "$target" --quiet && echo "GO" || echo "STOP"
```

---

### What's Tested

| Category | Tests | Coverage |
| --- | --- | --- |
| Asset Detection | 15 | Domain, wildcard, CIDR, IPv4, IPv6, URL, port, edge cases |
| Input Sanitizer | 9 | Protocol strip, null bytes, length limits, IDN/punycode |
| Domain Matching | 8 | Exact, wildcard, deep sub, apex, no-match |
| Exclusion Priority | 6 | Exact > wildcard, wildcard exclusion > wildcard inclusion |
| Wildcard Strict | 2 | Apex blocked in strict, subdomain still allowed |
| IPv4 | 14 | Exact, CIDR, exclusion, ranges, boundaries, invalid |
| IPv6 | 5 | CIDR, exclusion, exact, no-match |
| URL | 8 | Host, path exclusion, IP host, port enforcement |
| Port | 6 | Match, range, outside, no-restrictions, invalid |
| Host:Port | 3 | Both pass, port fail, host fail |
| Auto-detect | 6 | Domain, URL, IPv4, IPv6, empty, whitespace |
| Edge Cases | 6 | Case insensitive, trailing dot, empty scope, query strings |
| Batch | 4 | Parallel checking, ordering |
| Bounty | 3 | Tracking across match types |
| Scope Diff | 6 | Added/removed, no-change, from-none |
| Database | 10 | Roundtrip, duplicates, remove, delete, search, stats, backup |
| Parsers | 9 | YAML, JSON, text with full validation |
| Staleness | 4 | Fresh, stale, empty, bad date |
| Config | 3 | Set/get/persist credentials |
| IDN | 2 | Punycode conversion, ASCII passthrough |

---

## FAQ

### Q: Does `.example.com` match `example.com` itself?

**By default, yes.** Many bug bounty programs intend `*.example.com` to include
the apex domain. If a specific program means "subdomains only," use
`--wildcard-strict`:

```bash
scope_checker -p myprogram --wildcard-strict
```

This setting is saved per-program in the database.

### Q: What if an IP is both in an in-scope CIDR and explicitly excluded?

**Exclusion wins.** The matcher checks exclusion rules first, always:

```
In scope:  192.168.1.0/24
Excluded:  192.168.1.1

192.168.1.1  → OUT (excluded)
192.168.1.2  → IN  (CIDR match)
```

### Q: Can I use this without requests/pyyaml installed?

**Yes.** Core functionality works with Python stdlib only:

- JSON import/export ✅
- Text file import ✅
- All matching logic ✅
- SQLite database ✅
- Pipe filtering ✅

You only need `requests` for HackerOne/Bugcrowd API import, and `pyyaml` for
YAML import/export.

---

## Contributing

1. Fork the repository
2. Make your changes to `scope_checker.py`
3. Ensure `-self-test` passes with all 127 tests
4. Add new tests for any new functionality
5. Submit a pull request

### Running Tests

```bash
python scope_checker.py --self-test
```

All tests must pass. If you add a feature, add assertions to the `SelfTest`
class.

---

## Acknowledgments

Built for the bug bounty community. Inspired by the real pain of accidentally
testing out-of-scope targets at 3 AM.

---

<div align="center">

**Star ⭐ this repo if it saved you from an out-of-scope report.**

</div>

```
