from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import json
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a requested action violates or cannot load scope."""


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    allowed: bool
    reason: str
    matched: str | None = None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ScopeError(f"invalid expires timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_host(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ScopeError("empty target")

    if "://" in candidate:
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise ScopeError(f"URL has no host: {value!r}")
        return parsed.hostname.rstrip(".").lower()

    if candidate.startswith("[") and "]" in candidate:
        return candidate[1 : candidate.index("]")].lower()

    if candidate.count(":") == 1:
        host, maybe_port = candidate.rsplit(":", 1)
        if maybe_port.isdigit() and host:
            candidate = host

    return candidate.rstrip(".").lower()


def parse_ports(value: str | int | list[str | int] | tuple[str | int, ...]) -> tuple[int, ...]:
    if isinstance(value, int):
        values: list[str | int] = [value]
    elif isinstance(value, str):
        values = [part.strip() for part in value.split(",") if part.strip()]
    else:
        values = list(value)

    ports: set[int] = set()
    for item in values:
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise ScopeError(f"invalid port: {item!r}") from exc
        if not 1 <= port <= 65535:
            raise ScopeError(f"port out of range: {port}")
        ports.add(port)
    return tuple(sorted(ports))


def _same_ip_family(a: ipaddress._BaseNetwork, b: ipaddress._BaseNetwork) -> bool:
    return a.version == b.version


def _domain_matches(host: str, rule: str) -> bool:
    normalized_rule = rule.rstrip(".").lower()
    if normalized_rule.startswith("*."):
        suffix = normalized_rule[1:]
        return host.endswith(suffix) and host != normalized_rule[2:]
    return host == normalized_rule


@dataclass(frozen=True)
class Scope:
    path: Path
    engagement: str
    authorized_by: str
    expires: datetime
    cidrs: tuple[ipaddress._BaseNetwork, ...]
    domains: tuple[str, ...]
    ports: tuple[int, ...]
    evidence_dir: Path
    rate_limit_per_second: float
    max_hosts: int

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        scope_path = Path(path).expanduser().resolve()
        try:
            raw = json.loads(scope_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ScopeError(f"scope file not found: {scope_path}") from exc
        except json.JSONDecodeError as exc:
            raise ScopeError(f"invalid scope JSON: {exc}") from exc

        if not isinstance(raw, dict):
            raise ScopeError("scope file must contain a JSON object")

        engagement = str(raw.get("engagement") or "").strip()
        authorized_by = str(raw.get("authorized_by") or "").strip()
        expires = parse_timestamp(str(raw.get("expires") or ""))
        if not engagement:
            raise ScopeError("scope requires an engagement name")
        if not authorized_by:
            raise ScopeError("scope requires authorized_by")
        if expires is None:
            raise ScopeError("scope requires an expires timestamp")

        cidrs = []
        for item in raw.get("cidrs", []):
            try:
                cidrs.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError as exc:
                raise ScopeError(f"invalid CIDR: {item!r}") from exc

        domains = tuple(
            sorted(
                {
                    str(item).strip().rstrip(".").lower()
                    for item in raw.get("domains", [])
                    if str(item).strip()
                }
            )
        )

        if not cidrs and not domains:
            raise ScopeError("scope requires at least one CIDR or domain")

        ports = parse_ports(raw.get("ports", []))
        if not ports:
            raise ScopeError("scope requires at least one permitted port")

        rate_limit = float(raw.get("rate_limit_per_second", 25))
        if rate_limit <= 0:
            raise ScopeError("rate_limit_per_second must be positive")

        max_hosts = int(raw.get("max_hosts", 1024))
        if max_hosts < 1:
            raise ScopeError("max_hosts must be at least 1")

        evidence_value = str(raw.get("evidence_dir") or "evidence").strip()
        evidence_dir = Path(evidence_value).expanduser()
        if not evidence_dir.is_absolute():
            evidence_dir = (scope_path.parent / evidence_dir).resolve()
        else:
            evidence_dir = evidence_dir.resolve()

        return cls(
            path=scope_path,
            engagement=engagement,
            authorized_by=authorized_by,
            expires=expires,
            cidrs=tuple(cidrs),
            domains=domains,
            ports=ports,
            evidence_dir=evidence_dir,
            rate_limit_per_second=rate_limit,
            max_hosts=max_hosts,
        )

    @property
    def expired(self) -> bool:
        return utc_now() > self.expires

    def ensure_current(self) -> None:
        if self.expired:
            raise ScopeError(f"scope expired at {format_timestamp(self.expires)}")

    def allows_port(self, port: int) -> ScopeDecision:
        if port in self.ports:
            return ScopeDecision(str(port), True, "port is explicitly permitted", str(port))
        return ScopeDecision(str(port), False, "port is not listed in scope")

    def require_ports(self, ports: tuple[int, ...]) -> tuple[int, ...]:
        parsed = parse_ports(ports)
        for port in parsed:
            decision = self.allows_port(port)
            if not decision.allowed:
                raise ScopeError(f"port {port} is not permitted by scope")
        return parsed

    def allows_target(self, target: str) -> ScopeDecision:
        self.ensure_current()
        host = normalize_host(target)

        if "/" in host:
            try:
                requested_network = ipaddress.ip_network(host, strict=False)
            except ValueError:
                requested_network = None
            if requested_network is not None:
                for allowed_network in self.cidrs:
                    if _same_ip_family(requested_network, allowed_network) and requested_network.subnet_of(allowed_network):
                        return ScopeDecision(target, True, "CIDR is inside permitted scope", str(allowed_network))
                return ScopeDecision(target, False, "CIDR is outside permitted scope")

        try:
            requested_ip = ipaddress.ip_address(host)
        except ValueError:
            requested_ip = None

        if requested_ip is not None:
            for allowed_network in self.cidrs:
                if requested_ip.version == allowed_network.version and requested_ip in allowed_network:
                    return ScopeDecision(target, True, "IP is inside permitted scope", str(allowed_network))
            return ScopeDecision(target, False, "IP is outside permitted scope")

        for rule in self.domains:
            if _domain_matches(host, rule):
                return ScopeDecision(target, True, "domain matches permitted scope", rule)

        return ScopeDecision(target, False, "host is outside permitted scope")

    def require_target(self, target: str) -> ScopeDecision:
        decision = self.allows_target(target)
        if not decision.allowed:
            raise ScopeError(f"{target!r} blocked: {decision.reason}")
        return decision

    def require_url(self, url: str) -> tuple[str, int]:
        self.ensure_current()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError(f"unsupported URL scheme: {parsed.scheme or '<missing>'}")
        if not parsed.hostname:
            raise ScopeError(f"URL has no host: {url!r}")
        self.require_target(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.require_ports((port,))
        return parsed.hostname, port


def create_scope_document(
    *,
    engagement: str,
    authorized_by: str,
    expires: str,
    cidrs: tuple[str, ...],
    domains: tuple[str, ...],
    ports: tuple[int, ...],
    evidence_dir: str = "evidence",
    rate_limit_per_second: float = 25,
    max_hosts: int = 1024,
) -> dict[str, object]:
    document = {
        "engagement": engagement,
        "authorized_by": authorized_by,
        "expires": format_timestamp(parse_timestamp(expires)),
        "cidrs": list(cidrs),
        "domains": [domain.rstrip(".").lower() for domain in domains],
        "ports": list(parse_ports(ports)),
        "rate_limit_per_second": rate_limit_per_second,
        "max_hosts": max_hosts,
        "evidence_dir": evidence_dir,
    }
    validate_scope_document(document)
    return document


def write_scope_document(path: str | Path, document: dict[str, object]) -> Path:
    output_path = Path(path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return output_path


def validate_scope_document(document: dict[str, object]) -> None:
    engagement = str(document.get("engagement") or "").strip()
    authorized_by = str(document.get("authorized_by") or "").strip()
    expires = parse_timestamp(str(document.get("expires") or ""))
    cidrs = tuple(ipaddress.ip_network(str(item), strict=False) for item in document.get("cidrs", []))
    domains = tuple(str(item).strip() for item in document.get("domains", []) if str(item).strip())
    ports = parse_ports(document.get("ports", []))
    rate_limit = float(document.get("rate_limit_per_second", 25))
    max_hosts = int(document.get("max_hosts", 1024))

    if not engagement:
        raise ScopeError("scope requires an engagement name")
    if not authorized_by:
        raise ScopeError("scope requires authorized_by")
    if expires is None:
        raise ScopeError("scope requires an expires timestamp")
    if not cidrs and not domains:
        raise ScopeError("scope requires at least one CIDR or domain")
    if not ports:
        raise ScopeError("scope requires at least one permitted port")
    if rate_limit <= 0:
        raise ScopeError("rate_limit_per_second must be positive")
    if max_hosts < 1:
        raise ScopeError("max_hosts must be at least 1")
