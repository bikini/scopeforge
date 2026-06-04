from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
from typing import Iterable, Any

from .scanner import RateLimiter, expand_targets
from .scope import Scope, ScopeError, parse_ports, utc_now


@dataclass(frozen=True)
class TlsProbeResult:
    host: str
    port: int
    state: str
    tls_version: str | None = None
    cipher: str | None = None
    subject: dict[str, str] | None = None
    issuer: dict[str, str] | None = None
    subject_alt_names: list[str] | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    cert_sha256: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "subject": self.subject or {},
            "issuer": self.issuer or {},
            "subject_alt_names": self.subject_alt_names or [],
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_until_expiry": self.days_until_expiry,
            "cert_sha256": self.cert_sha256,
            "error": self.error,
        }


def _name_tuple_to_dict(value: tuple[tuple[tuple[str, str], ...], ...] | tuple[Any, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for rdn in value:
        for key, item in rdn:
            result[str(key)] = str(item)
    return result


def _cert_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        seconds = ssl.cert_time_to_seconds(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _days_until(value: str | None) -> int | None:
    if not value:
        return None
    try:
        expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    delta = expires - utc_now()
    return int(delta.total_seconds() // 86400)


def _subject_alt_names(cert: dict[str, Any]) -> list[str]:
    names = []
    for kind, value in cert.get("subjectAltName", ()):
        if kind in {"DNS", "IP Address"}:
            names.append(str(value))
    return sorted(set(names))


def _decode_certificate(binary_cert: bytes | None) -> dict[str, Any]:
    if not binary_cert:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(binary_cert)
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False) as handle:
            handle.write(pem)
            temp_path = handle.name
        return ssl._ssl._test_decode_cert(temp_path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass


def _server_hostname(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _probe_tls(host: str, port: int, timeout: float, limiter: RateLimiter) -> TlsProbeResult:
    limiter.wait()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=_server_hostname(host)) as tls_socket:
                binary_cert = tls_socket.getpeercert(binary_form=True)
                cert = tls_socket.getpeercert() or _decode_certificate(binary_cert)
                not_before = _cert_timestamp(cert.get("notBefore"))
                not_after = _cert_timestamp(cert.get("notAfter"))
                cipher = tls_socket.cipher()
                return TlsProbeResult(
                    host=host,
                    port=port,
                    state="tls",
                    tls_version=tls_socket.version(),
                    cipher=cipher[0] if cipher else None,
                    subject=_name_tuple_to_dict(cert.get("subject", ())),
                    issuer=_name_tuple_to_dict(cert.get("issuer", ())),
                    subject_alt_names=_subject_alt_names(cert),
                    not_before=not_before,
                    not_after=not_after,
                    days_until_expiry=_days_until(not_after),
                    cert_sha256=hashlib.sha256(binary_cert).hexdigest() if binary_cert else None,
                )
    except ssl.SSLError as exc:
        return TlsProbeResult(host=host, port=port, state="not_tls", error=str(exc))
    except socket.timeout:
        return TlsProbeResult(host=host, port=port, state="filtered", error="timeout")
    except OSError as exc:
        return TlsProbeResult(host=host, port=port, state="closed", error=str(exc))


def probe_tls(
    scope: Scope,
    *,
    targets: Iterable[str],
    ports: Iterable[int] | str,
    timeout: float = 3.0,
    workers: int = 32,
) -> list[TlsProbeResult]:
    scope.ensure_current()
    parsed_ports = scope.require_ports(parse_ports(ports))
    expanded_targets = expand_targets(scope, targets)
    if not expanded_targets:
        raise ScopeError("at least one target is required")
    if timeout <= 0:
        raise ScopeError("timeout must be positive")
    if workers < 1:
        raise ScopeError("workers must be at least 1")

    limiter = RateLimiter(scope.rate_limit_per_second)
    jobs = [(host, port) for host in expanded_targets for port in parsed_ports]
    results: list[TlsProbeResult] = []

    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as pool:
        futures = [pool.submit(_probe_tls, host, port, timeout, limiter) for host, port in jobs]
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda item: (item.host, item.port))
