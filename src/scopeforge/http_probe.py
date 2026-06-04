from __future__ import annotations

from dataclasses import dataclass
import html
import re
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__
from .scope import Scope, ScopeError


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
INTERESTING_HEADERS = (
    "Server",
    "Content-Type",
    "Content-Length",
    "Location",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
)


@dataclass(frozen=True)
class HttpProbeResult:
    url: str
    final_url: str | None
    status: int | None
    title: str | None
    headers: dict[str, str]
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "title": self.title,
            "headers": self.headers,
            "error": self.error,
        }


class ScopedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, scope: Scope) -> None:
        super().__init__()
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.scope.require_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _extract_title(body: bytes) -> str | None:
    text = body[:65536].decode("utf-8", errors="replace")
    match = TITLE_RE.search(text)
    if not match:
        return None
    title = html.unescape(match.group(1))
    return " ".join(title.split())[:160] or None


def _interesting_headers(headers) -> dict[str, str]:  # type: ignore[no-untyped-def]
    selected: dict[str, str] = {}
    for name in INTERESTING_HEADERS:
        value = headers.get(name)
        if value is not None:
            selected[name] = str(value)
    return selected


def probe_http_url(scope: Scope, url: str, *, timeout: float = 5.0) -> HttpProbeResult:
    scope.require_url(url)
    if timeout <= 0:
        raise ScopeError("timeout must be positive")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ScopeError(f"unsupported URL scheme: {parsed.scheme or '<missing>'}")

    request = Request(
        url,
        headers={
            "User-Agent": f"ScopeForge/{__version__} authorized-research",
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.8,*/*;q=0.5",
        },
        method="GET",
    )
    opener = build_opener(ScopedRedirectHandler(scope))

    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(65536)
            final_url = response.geturl()
            scope.require_url(final_url)
            return HttpProbeResult(
                url=url,
                final_url=final_url,
                status=response.status,
                title=_extract_title(body),
                headers=_interesting_headers(response.headers),
            )
    except HTTPError as exc:
        body = exc.read(65536)
        final_url = exc.geturl()
        if final_url:
            scope.require_url(final_url)
        return HttpProbeResult(
            url=url,
            final_url=final_url,
            status=exc.code,
            title=_extract_title(body),
            headers=_interesting_headers(exc.headers),
            error=f"HTTP {exc.code}",
        )
    except URLError as exc:
        return HttpProbeResult(
            url=url,
            final_url=None,
            status=None,
            title=None,
            headers={},
            error=str(exc.reason),
        )
    except OSError as exc:
        return HttpProbeResult(
            url=url,
            final_url=None,
            status=None,
            title=None,
            headers={},
            error=str(exc),
        )


def probe_http(scope: Scope, urls: Iterable[str], *, timeout: float = 5.0) -> list[HttpProbeResult]:
    results = [probe_http_url(scope, url, timeout=timeout) for url in urls]
    if not results:
        raise ScopeError("at least one URL is required")
    return results
