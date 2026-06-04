from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json
from typing import Any
from urllib.parse import urlparse

from .ledger import EvidenceLedger


def _host_port_from_url(url: str) -> tuple[str | None, int | None]:
    parsed = urlparse(url)
    if not parsed.hostname:
        return None, None
    return parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def _asset(assets: dict[str, dict[str, Any]], host: str) -> dict[str, Any]:
    if host not in assets:
        assets[host] = {
            "host": host,
            "open_ports": [],
            "services": {},
            "http": [],
            "tls": [],
        }
    return assets[host]


def _service_key(port: int, protocol: str) -> str:
    return f"{port}/{protocol}"


def build_inventory(events: list[dict[str, Any]]) -> dict[str, Any]:
    assets: dict[str, dict[str, Any]] = {}
    action_counts: dict[str, int] = defaultdict(int)

    for event in events:
        if event.get("status") != "completed":
            continue
        action = str(event.get("action") or "")
        action_counts[action] += 1
        data = event.get("data", {})
        if not isinstance(data, dict):
            continue

        if action == "tcp_scan":
            for result in data.get("results", []):
                if not isinstance(result, dict) or result.get("state") != "open":
                    continue
                host = str(result.get("host") or "")
                port = result.get("port")
                if not host or not isinstance(port, int):
                    continue
                asset = _asset(assets, host)
                if port not in asset["open_ports"]:
                    asset["open_ports"].append(port)
                asset["services"][_service_key(port, "tcp")] = {
                    "state": "open",
                    "last_seen": event.get("ts"),
                    "source": "tcp_scan",
                }

        if action == "http_probe":
            for result in data.get("results", []):
                if not isinstance(result, dict):
                    continue
                url = str(result.get("final_url") or result.get("url") or "")
                host, port = _host_port_from_url(url)
                if not host or port is None:
                    continue
                asset = _asset(assets, host)
                protocol = "https" if urlparse(url).scheme == "https" else "http"
                asset["services"][_service_key(port, protocol)] = {
                    "state": "observed",
                    "last_seen": event.get("ts"),
                    "source": "http_probe",
                    "status": result.get("status"),
                    "title": result.get("title"),
                }
                asset["http"].append(
                    {
                        "url": result.get("url"),
                        "final_url": result.get("final_url"),
                        "status": result.get("status"),
                        "title": result.get("title"),
                        "findings": result.get("findings", []),
                    }
                )

        if action == "tls_probe":
            for result in data.get("results", []):
                if not isinstance(result, dict) or result.get("state") != "tls":
                    continue
                host = str(result.get("host") or "")
                port = result.get("port")
                if not host or not isinstance(port, int):
                    continue
                asset = _asset(assets, host)
                asset["services"][_service_key(port, "tls")] = {
                    "state": "observed",
                    "last_seen": event.get("ts"),
                    "source": "tls_probe",
                    "tls_version": result.get("tls_version"),
                    "cert_sha256": result.get("cert_sha256"),
                }
                asset["tls"].append(
                    {
                        "port": port,
                        "tls_version": result.get("tls_version"),
                        "cipher": result.get("cipher"),
                        "subject": result.get("subject", {}),
                        "issuer": result.get("issuer", {}),
                        "subject_alt_names": result.get("subject_alt_names", []),
                        "not_after": result.get("not_after"),
                        "days_until_expiry": result.get("days_until_expiry"),
                        "cert_sha256": result.get("cert_sha256"),
                    }
                )

    normalized_assets = []
    for host in sorted(assets):
        asset = assets[host]
        asset["open_ports"] = sorted(asset["open_ports"])
        asset["services"] = dict(sorted(asset["services"].items()))
        normalized_assets.append(asset)

    return {
        "summary": {
            "asset_count": len(normalized_assets),
            "service_count": sum(len(asset["services"]) for asset in normalized_assets),
            "action_counts": dict(sorted(action_counts.items())),
        },
        "assets": normalized_assets,
    }


def inventory_from_ledger(ledger: EvidenceLedger) -> dict[str, Any]:
    return build_inventory(ledger.read_events())


def write_inventory_json(inventory: dict[str, Any], output: str | Path) -> Path:
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(inventory, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return output_path


def service_set(inventory: dict[str, Any]) -> set[tuple[str, str]]:
    services: set[tuple[str, str]] = set()
    for asset in inventory.get("assets", []):
        if not isinstance(asset, dict):
            continue
        host = str(asset.get("host") or "")
        service_map = asset.get("services", {})
        if not host or not isinstance(service_map, dict):
            continue
        for service in service_map:
            services.add((host, str(service)))
    return services


def diff_inventories(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_services = service_set(before)
    after_services = service_set(after)
    added = sorted(after_services - before_services)
    removed = sorted(before_services - after_services)
    unchanged = sorted(after_services & before_services)
    return {
        "added_services": [{"host": host, "service": service} for host, service in added],
        "removed_services": [{"host": host, "service": service} for host, service in removed],
        "unchanged_service_count": len(unchanged),
        "before_service_count": len(before_services),
        "after_service_count": len(after_services),
    }


def read_ledger_events(path: str | Path) -> list[dict[str, Any]]:
    ledger_path = Path(path).expanduser().resolve()
    events: list[dict[str, Any]] = []
    if not ledger_path.exists():
        raise FileNotFoundError(ledger_path)
    with ledger_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                value = json.loads(stripped)
                if isinstance(value, dict):
                    events.append(value)
    return events
