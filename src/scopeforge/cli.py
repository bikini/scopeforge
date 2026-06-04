from __future__ import annotations

import argparse
from datetime import timedelta
import getpass
import json
from pathlib import Path
import sys

from . import __version__
from .http_probe import probe_http
from .ledger import EvidenceLedger
from .report import write_html_report
from .scanner import expand_targets, scan_tcp
from .scope import (
    Scope,
    ScopeDecision,
    ScopeError,
    create_scope_document,
    format_timestamp,
    parse_ports,
    utc_now,
    write_scope_document,
)


def _load_scope(args: argparse.Namespace) -> Scope:
    return Scope.load(args.scope)


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _decision_dict(decision: ScopeDecision) -> dict[str, object]:
    return {
        "target": decision.target,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "matched": decision.matched,
    }


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser().resolve()
    if path.exists() and not args.force:
        raise ScopeError(f"refusing to overwrite existing scope file: {path}")

    expires = args.expires
    if not expires:
        expires = format_timestamp(utc_now() + timedelta(days=args.days)) or ""

    cidrs = tuple(args.cidr or ("127.0.0.1/32",))
    domains = tuple(args.domain or ("localhost",))
    ports = parse_ports(args.ports)
    document = create_scope_document(
        engagement=args.engagement,
        authorized_by=args.authorized_by,
        expires=expires,
        cidrs=cidrs,
        domains=domains,
        ports=ports,
        evidence_dir=args.evidence_dir,
        rate_limit_per_second=args.rate_limit,
        max_hosts=args.max_hosts,
    )
    output = write_scope_document(path, document)
    print(f"created scope file: {output}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    decisions = [scope.allows_target(target) for target in args.targets]
    if args.json:
        _print_json([_decision_dict(decision) for decision in decisions])
    else:
        for decision in decisions:
            status = "ALLOW" if decision.allowed else "BLOCK"
            matched = f" ({decision.matched})" if decision.matched else ""
            print(f"{status:<5} {decision.target} - {decision.reason}{matched}")
    return 0 if all(decision.allowed for decision in decisions) else 2


def cmd_plan(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    ports = scope.require_ports(parse_ports(args.ports or scope.ports))
    targets = expand_targets(scope, args.target)
    plan = {
        "engagement": scope.engagement,
        "targets": list(targets),
        "ports": list(ports),
        "probe_count": len(targets) * len(ports),
        "rate_limit_per_second": scope.rate_limit_per_second,
        "commands": [
            f"scopeforge check --scope {scope.path} " + " ".join(targets),
            f"scopeforge scan --scope {scope.path} --ports {','.join(str(port) for port in ports)} "
            + " ".join(f"--target {target}" for target in targets),
        ],
    }
    if args.json:
        _print_json(plan)
    else:
        print(f"Engagement: {plan['engagement']}")
        print(f"Targets: {len(targets)}")
        print(f"Ports: {', '.join(str(port) for port in ports)}")
        print(f"TCP probes: {plan['probe_count']}")
        print(f"Rate limit: {scope.rate_limit_per_second:g}/second")
        print("Suggested sequence:")
        for command in plan["commands"]:
            print(f"  {command}")
    return 0


def _print_scan_table(results: list[dict[str, object]]) -> None:
    print(f"{'HOST':<39} {'PORT':>5} {'STATE':<8} {'LATENCY_MS':>10}")
    print(f"{'-' * 39} {'-' * 5} {'-' * 8} {'-' * 10}")
    for result in results:
        print(
            f"{str(result['host'])[:39]:<39} "
            f"{int(result['port']):>5} "
            f"{str(result['state']):<8} "
            f"{float(result['latency_ms']):>10.2f}"
        )


def cmd_scan(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    ledger = EvidenceLedger(scope)
    ports = parse_ports(args.ports or scope.ports)
    started = ledger.append(
        "tcp_scan",
        "started",
        {
            "targets": args.target,
            "ports": list(ports),
            "timeout": args.timeout,
            "workers": args.workers,
        },
    )
    try:
        results = scan_tcp(
            scope,
            targets=args.target,
            ports=ports,
            timeout=args.timeout,
            workers=args.workers,
        )
    except Exception as exc:
        ledger.append(
            "tcp_scan",
            "failed",
            {
                "started_entry_sha256": started["entry_sha256"],
                "error": str(exc),
            },
        )
        raise

    result_dicts = [result.as_dict() for result in results]
    open_count = sum(1 for result in results if result.state == "open")
    ledger.append(
        "tcp_scan",
        "completed",
        {
            "started_entry_sha256": started["entry_sha256"],
            "targets": args.target,
            "ports": list(ports),
            "probe_count": len(results),
            "open_count": open_count,
            "results": result_dicts,
        },
    )
    if args.json:
        _print_json(result_dicts)
    else:
        _print_scan_table(result_dicts)
        print(f"open ports: {open_count}; ledger: {ledger.path}")
    return 0


def _print_http_table(results: list[dict[str, object]]) -> None:
    print(f"{'STATUS':>6} {'URL':<52} TITLE")
    print(f"{'-' * 6} {'-' * 52} {'-' * 40}")
    for result in results:
        status = result["status"] if result["status"] is not None else "ERR"
        title = result["title"] or result["error"] or ""
        print(f"{str(status):>6} {str(result['url'])[:52]:<52} {str(title)[:80]}")


def cmd_http(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    ledger = EvidenceLedger(scope)
    started = ledger.append(
        "http_probe",
        "started",
        {
            "urls": args.url,
            "timeout": args.timeout,
        },
    )
    try:
        results = probe_http(scope, args.url, timeout=args.timeout)
    except Exception as exc:
        ledger.append(
            "http_probe",
            "failed",
            {
                "started_entry_sha256": started["entry_sha256"],
                "error": str(exc),
            },
        )
        raise

    result_dicts = [result.as_dict() for result in results]
    ledger.append(
        "http_probe",
        "completed",
        {
            "started_entry_sha256": started["entry_sha256"],
            "urls": args.url,
            "results": result_dicts,
        },
    )
    if args.json:
        _print_json(result_dicts)
    else:
        _print_http_table(result_dicts)
        print(f"ledger: {ledger.path}")
    return 0


def cmd_ledger(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    ledger = EvidenceLedger(scope)
    verification = ledger.verify()
    if args.json:
        _print_json(
            {
                "valid": verification.valid,
                "entries": verification.entries,
                "last_hash": verification.last_hash,
                "errors": list(verification.errors),
                "path": str(ledger.path),
            }
        )
    else:
        status = "valid" if verification.valid else "invalid"
        print(f"ledger {status}: {ledger.path}")
        print(f"entries: {verification.entries}")
        print(f"last hash: {verification.last_hash or 'none'}")
        for error in verification.errors:
            print(f"error: {error}", file=sys.stderr)
    return 0 if verification.valid else 3


def cmd_report(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    ledger = EvidenceLedger(scope)
    output = write_html_report(scope, ledger, args.out)
    print(f"wrote report: {output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopeforge",
        description="Scope-enforced recon and evidence tooling for authorized security work.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create a scope JSON file")
    init.add_argument("--path", default="scopeforge.scope.json", help="scope file path")
    init.add_argument("--engagement", default="Authorized Lab", help="engagement name")
    init.add_argument("--authorized-by", default=getpass.getuser(), help="authorizing person or team")
    init.add_argument("--expires", help="ISO timestamp, for example 2026-12-31T23:59:59Z")
    init.add_argument("--days", type=int, default=90, help="expiry in days when --expires is omitted")
    init.add_argument("--cidr", action="append", help="permitted CIDR; may be repeated")
    init.add_argument("--domain", action="append", help="permitted domain or wildcard domain; may be repeated")
    init.add_argument("--ports", default="80,443,8000,8080,8443", help="comma-separated permitted ports")
    init.add_argument("--evidence-dir", default="evidence", help="evidence output directory")
    init.add_argument("--rate-limit", type=float, default=25, help="maximum active probes per second")
    init.add_argument("--max-hosts", type=int, default=1024, help="maximum hosts expanded from a CIDR")
    init.add_argument("--force", action="store_true", help="overwrite an existing scope file")
    init.set_defaults(func=cmd_init)

    check = subparsers.add_parser("check", help="check whether targets are in scope")
    check.add_argument("--scope", required=True, help="scope file path")
    check.add_argument("--json", action="store_true", help="print JSON")
    check.add_argument("targets", nargs="+", help="IPs, CIDRs, hostnames, or URLs")
    check.set_defaults(func=cmd_check)

    plan = subparsers.add_parser("plan", help="show a scoped probing plan without network activity")
    plan.add_argument("--scope", required=True, help="scope file path")
    plan.add_argument("--target", action="append", required=True, help="target IP, CIDR, hostname, or URL")
    plan.add_argument("--ports", help="comma-separated ports; defaults to scope ports")
    plan.add_argument("--json", action="store_true", help="print JSON")
    plan.set_defaults(func=cmd_plan)

    scan = subparsers.add_parser("scan", help="run scoped TCP connect probes")
    scan.add_argument("--scope", required=True, help="scope file path")
    scan.add_argument("--target", action="append", required=True, help="target IP, CIDR, hostname, or URL")
    scan.add_argument("--ports", help="comma-separated ports; defaults to scope ports")
    scan.add_argument("--timeout", type=float, default=1.0, help="TCP connect timeout in seconds")
    scan.add_argument("--workers", type=int, default=64, help="concurrent worker count")
    scan.add_argument("--json", action="store_true", help="print JSON")
    scan.set_defaults(func=cmd_scan)

    http = subparsers.add_parser("http", help="run scoped HTTP probes")
    http.add_argument("--scope", required=True, help="scope file path")
    http.add_argument("--url", action="append", required=True, help="HTTP or HTTPS URL")
    http.add_argument("--timeout", type=float, default=5.0, help="request timeout in seconds")
    http.add_argument("--json", action="store_true", help="print JSON")
    http.set_defaults(func=cmd_http)

    ledger = subparsers.add_parser("ledger", help="inspect or verify the evidence ledger")
    ledger.add_argument("--scope", required=True, help="scope file path")
    ledger.add_argument("--verify", action="store_true", help="verify the ledger hash chain")
    ledger.add_argument("--json", action="store_true", help="print JSON")
    ledger.set_defaults(func=cmd_ledger)

    report = subparsers.add_parser("report", help="render an HTML report from the evidence ledger")
    report.add_argument("--scope", required=True, help="scope file path")
    report.add_argument("--out", default="evidence/report.html", help="HTML report path")
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ScopeError as exc:
        print(f"scopeforge: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("scopeforge: interrupted", file=sys.stderr)
        return 130
