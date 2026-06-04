# ScopeForge

ScopeForge is a scope-enforced reconnaissance CLI for authorized offensive
security work. It helps researchers run bounded TCP and HTTP checks, prove that
targets were in scope, and keep a tamper-evident evidence ledger for reports.

It is not a pivoting framework, implant, exploit kit, or stealth tool. Every
active operation must pass an explicit scope check before it runs.

## Features

- JSON scope files with CIDR, domain, port, expiry, and rate-limit controls.
- Target guard that refuses out-of-scope IPs, CIDRs, hostnames, and URLs.
- Concurrent TCP connect probing with host-count limits and rate limiting.
- HTTP title/header/status fingerprinting for scoped URLs.
- Hash-chained JSONL evidence ledger.
- Standalone HTML report generation from the evidence ledger.
- Dependency-free runtime on Python 3.11+.

## Quick Start

```powershell
cd C:\Users\Owner\Desktop\software\development\scopeforge
python -m scopeforge init --path scopeforge.scope.json --engagement "Local Lab" --authorized-by "Owner" --cidr 127.0.0.1/32 --domain localhost --ports 80,443,8000,8080 --expires 2026-12-31T23:59:59Z
python -m scopeforge check --scope scopeforge.scope.json 127.0.0.1 localhost
python -m scopeforge scan --scope scopeforge.scope.json --target 127.0.0.1 --ports 80,443,8000,8080
python -m scopeforge http --scope scopeforge.scope.json http://localhost:8000/
python -m scopeforge ledger --scope scopeforge.scope.json --verify
python -m scopeforge report --scope scopeforge.scope.json --out evidence/report.html
```

From a virtual environment, install the CLI command:

```powershell
python -m pip install -e .
scopeforge --help
```

## Scope File

See `examples/scope.example.json` for a complete example.

```json
{
  "engagement": "Local Lab",
  "authorized_by": "Owner",
  "expires": "2026-12-31T23:59:59Z",
  "cidrs": ["127.0.0.1/32"],
  "domains": ["localhost", "*.lab.example"],
  "ports": [80, 443, 8000, 8080],
  "rate_limit_per_second": 25,
  "max_hosts": 1024,
  "evidence_dir": "evidence"
}
```

## Commands

- `init`: create a scope file.
- `check`: explain whether targets are allowed by the loaded scope.
- `plan`: summarize a safe probing plan for scoped targets and ports.
- `scan`: run scoped TCP connect probes.
- `http`: collect scoped HTTP status, headers, and page title.
- `ledger --verify`: validate the evidence ledger hash chain.
- `report`: render a standalone HTML report from ledger events.

## Responsible Use

Only use ScopeForge where you have permission. The tool is intentionally
designed to make authorization visible and auditable.
