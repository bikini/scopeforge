from __future__ import annotations

from collections import Counter
from datetime import timezone
from pathlib import Path
import html
import json
from typing import Any

from .inventory import build_inventory
from .ledger import EvidenceLedger
from .scope import Scope, utc_now


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _event_summary(events: list[dict[str, Any]]) -> Counter[str]:
    summary: Counter[str] = Counter()
    for event in events:
        action = str(event.get("action") or "unknown")
        status = str(event.get("status") or "unknown")
        summary[f"{action}:{status}"] += 1
    return summary


def _render_event_rows(events: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for event in events:
        data = json.dumps(event.get("data", {}), indent=2, sort_keys=True, ensure_ascii=False)
        rows.append(
            "<tr>"
            f"<td>{_escape(event.get('ts', ''))}</td>"
            f"<td>{_escape(event.get('action', ''))}</td>"
            f"<td>{_escape(event.get('status', ''))}</td>"
            f"<td><code>{_escape(event.get('entry_sha256', ''))}</code></td>"
            f"<td><pre>{_escape(data)}</pre></td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_asset_rows(inventory: dict[str, Any]) -> str:
    rows: list[str] = []
    for asset in inventory.get("assets", []):
        if not isinstance(asset, dict):
            continue
        services = asset.get("services", {})
        http = asset.get("http", [])
        tls = asset.get("tls", [])
        service_names = ", ".join(services.keys()) if isinstance(services, dict) else ""
        http_titles = []
        if isinstance(http, list):
            for item in http:
                if isinstance(item, dict) and item.get("title"):
                    http_titles.append(str(item["title"]))
        tls_expiry = []
        if isinstance(tls, list):
            for item in tls:
                if isinstance(item, dict) and item.get("not_after"):
                    tls_expiry.append(f"{item.get('port')}: {item.get('not_after')}")
        rows.append(
            "<tr>"
            f"<td>{_escape(asset.get('host', ''))}</td>"
            f"<td>{_escape(', '.join(str(port) for port in asset.get('open_ports', [])))}</td>"
            f"<td>{_escape(service_names)}</td>"
            f"<td>{_escape('; '.join(http_titles[:4]))}</td>"
            f"<td>{_escape('; '.join(tls_expiry[:4]))}</td>"
            "</tr>"
        )
    return "\n".join(rows) or '<tr><td colspan="5">No assets discovered in ledger evidence.</td></tr>'


def render_html_report(scope: Scope, ledger: EvidenceLedger) -> str:
    events = ledger.read_events()
    verification = ledger.verify()
    inventory = build_inventory(events)
    summary = _event_summary(events)
    generated_at = utc_now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    summary_items = "\n".join(
        f"<li><strong>{_escape(key)}</strong>: {_escape(value)}</li>"
        for key, value in sorted(summary.items())
    ) or "<li>No ledger events found.</li>"
    errors = "\n".join(f"<li>{_escape(error)}</li>" for error in verification.errors)
    if not errors:
        errors = "<li>Ledger hash chain is valid.</li>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ScopeForge Report - {_escape(scope.engagement)}</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }}
    body {{
      margin: 0;
      background: #f6f7f9;
      color: #141820;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    h1, h2 {{
      line-height: 1.15;
    }}
    .meta, .summary, .verify {{
      background: #ffffff;
      border: 1px solid #dce1e8;
      border-radius: 8px;
      padding: 18px;
      margin: 16px 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #ffffff;
      border: 1px solid #dce1e8;
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid #e7ebf0;
      padding: 10px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      background: #eef2f6;
      font-weight: 700;
    }}
    code, pre {{
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }}
    .ok {{
      color: #0b6b3a;
      font-weight: 700;
    }}
    .bad {{
      color: #a11d1d;
      font-weight: 700;
    }}
  </style>
</head>
<body>
<main>
  <h1>ScopeForge Report</h1>
  <section class="meta">
    <p><strong>Engagement:</strong> {_escape(scope.engagement)}</p>
    <p><strong>Authorized by:</strong> {_escape(scope.authorized_by)}</p>
    <p><strong>Scope file:</strong> {_escape(scope.path)}</p>
    <p><strong>Generated:</strong> {_escape(generated_at)}</p>
    <p><strong>Ledger:</strong> {_escape(ledger.path)}</p>
  </section>
  <section class="verify">
    <h2>Ledger Verification</h2>
    <p class="{ 'ok' if verification.valid else 'bad' }">
      { 'Valid' if verification.valid else 'Invalid' } hash chain,
      {_escape(verification.entries)} entries,
      last hash {_escape(verification.last_hash or 'none')}.
    </p>
    <ul>{errors}</ul>
  </section>
  <section class="summary">
    <h2>Summary</h2>
    <ul>{summary_items}</ul>
  </section>
  <h2>Asset Inventory</h2>
  <table>
    <thead>
      <tr>
        <th>Host</th>
        <th>Open Ports</th>
        <th>Services</th>
        <th>HTTP Titles</th>
        <th>TLS Expiry</th>
      </tr>
    </thead>
    <tbody>
      {_render_asset_rows(inventory)}
    </tbody>
  </table>
  <h2>Events</h2>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Action</th>
        <th>Status</th>
        <th>Entry Hash</th>
        <th>Data</th>
      </tr>
    </thead>
    <tbody>
      {_render_event_rows(events)}
    </tbody>
  </table>
</main>
</body>
</html>
"""


def write_html_report(scope: Scope, ledger: EvidenceLedger, output: str | Path) -> Path:
    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = (scope.path.parent / output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html_report(scope, ledger), encoding="utf-8")
    return output_path
