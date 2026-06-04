from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import socket
import threading
import time
from typing import Iterable

from .scope import Scope, ScopeError, normalize_host, parse_ports


@dataclass(frozen=True)
class TcpProbeResult:
    host: str
    port: int
    state: str
    latency_ms: float
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
        }


class RateLimiter:
    def __init__(self, per_second: float) -> None:
        self.interval = 1.0 / per_second
        self.lock = threading.Lock()
        self.next_at = 0.0

    def wait(self) -> None:
        with self.lock:
            now = time.perf_counter()
            if now < self.next_at:
                time.sleep(self.next_at - now)
                now = time.perf_counter()
            self.next_at = max(now, self.next_at) + self.interval


def expand_targets(scope: Scope, targets: Iterable[str]) -> tuple[str, ...]:
    expanded: list[str] = []
    seen: set[str] = set()

    for target in targets:
        scope.require_target(target)
        host = normalize_host(target)
        network = None
        if "/" in host:
            try:
                network = ipaddress.ip_network(host, strict=False)
            except ValueError:
                network = None

        if network is None:
            if host not in seen:
                expanded.append(host)
                seen.add(host)
            continue

        if network.num_addresses > scope.max_hosts:
            raise ScopeError(
                f"{network} has {network.num_addresses} addresses; "
                f"scope max_hosts is {scope.max_hosts}"
            )

        hosts = list(network.hosts())
        if not hosts:
            hosts = [network.network_address]
        for ip in hosts:
            value = str(ip)
            if value not in seen:
                expanded.append(value)
                seen.add(value)

    return tuple(expanded)


def _probe_tcp(host: str, port: int, timeout: float, limiter: RateLimiter) -> TcpProbeResult:
    limiter.wait()
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = (time.perf_counter() - started) * 1000
            return TcpProbeResult(host, port, "open", latency_ms)
    except socket.timeout:
        latency_ms = (time.perf_counter() - started) * 1000
        return TcpProbeResult(host, port, "filtered", latency_ms, "timeout")
    except OSError as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        return TcpProbeResult(host, port, "closed", latency_ms, str(exc))


def scan_tcp(
    scope: Scope,
    *,
    targets: Iterable[str],
    ports: Iterable[int] | str,
    timeout: float = 1.0,
    workers: int = 64,
) -> list[TcpProbeResult]:
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
    max_workers = min(workers, len(jobs))
    results: list[TcpProbeResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_probe_tcp, host, port, timeout, limiter): (host, port)
            for host, port in jobs
        }
        for future in as_completed(future_map):
            results.append(future.result())

    return sorted(results, key=lambda item: (item.host, item.port))
