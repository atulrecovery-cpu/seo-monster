"""Generic HTTP client for the technical-SEO tools.

Five v0.3.0 tools fetch arbitrary public URLs: ``inspect_meta``,
``check_canonical``, ``mixed_content_check``, ``redirect_chain_audit``,
``robots_txt_validate``, ``sitemap_validate``, ``sitemap_health``. Rather
than each tool wiring its own ``urllib`` boilerplate, they all share this
client. Tests monkeypatch the single ``_http_request_raw`` seam.

Design decisions:

- We do **not** auto-follow redirects at the urllib layer. We follow them
  ourselves so the caller (``redirect_chain_audit``) can see every hop. Other
  tools opt in via ``follow_redirects=True`` and just get the final response.
- We cap the response body at ``max_bytes`` (default 10 MiB). A typical SEO
  page is well under that; capping keeps a misconfigured server from blowing
  out memory.
- We cap the redirect chain at ``max_redirects`` (default 10) and surface a
  loop as ``UPSTREAM_ERROR`` so the tool layer can describe it.
- We send a clearly-identified User-Agent. Crawlers that hide their identity
  are widely blocked, and SEO tools should announce themselves.
"""

from __future__ import annotations

import contextvars
import http.client
import ipaddress
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .. import __version__
from ..errors import ErrorCode
from .errors import ApiError, _redact_sensitive_text


# Derived from the package version rather than hardcoded: this string drifted
# behind the real version for several releases because it was a literal, and a
# release-gate check does not cover it (see PLAN §11.4.2).
_USER_AGENT = f"SEOMonster/{__version__} (+https://seomonster.avansaber.com)"
_DEFAULT_TIMEOUT = 20
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_MAX_REDIRECTS = 10

_PINNED_IP: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "seo_mcp_http_pinned_ip", default=None
)


def _validate_public_url(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ApiError(ErrorCode.INVALID_INPUT, "URL must use http:// or https:// and include a hostname.")

    try:
        addresses = [ipaddress.ip_address(parsed.hostname)]
    except ValueError:
        try:
            results = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ApiError(ErrorCode.UPSTREAM_ERROR, f"Could not resolve URL hostname {parsed.hostname!r}.") from exc
        addresses = [ipaddress.ip_address(result[4][0]) for result in results]

    if not addresses or any(not address.is_global for address in addresses):
        raise ApiError(ErrorCode.INVALID_INPUT, f"URL target {parsed.hostname!r} resolves to a non-public IP address.")

    return [str(address) for address in addresses]


@dataclass
class RedirectHop:
    """One step in a redirect chain."""

    url: str
    status: int
    location: str | None
    elapsed_ms: int


@dataclass
class HttpResponse:
    """Result of a single HTTP request (or a followed redirect chain).

    ``redirect_chain`` is the ordered list of hops *before* the final
    response; the final response itself is described by ``status``,
    ``headers``, ``body_text``, and ``final_url``.
    """

    status: int
    headers: dict[str, str]
    body_bytes: bytes
    final_url: str
    redirect_chain: list[RedirectHop] = field(default_factory=list)

    @property
    def body_text(self) -> str:
        """Best-effort decode. Falls back to latin-1 so we never raise."""
        ctype = self.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return self.body_bytes.decode(charset, errors="replace")
        except LookupError:
            return self.body_bytes.decode("utf-8", errors="replace")


def _connect_pinned(
    ip: str,
    port: int,
    timeout: float | None,
) -> socket.socket:
    """Connect directly to a previously validated numeric IP."""
    address = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET

    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        target = (ip, port, 0, 0) if address.version == 6 else (ip, port)
        sock.connect(target)
        return sock
    except Exception:
        sock.close()
        raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(
        self,
        host: str,
        pinned_ip: str,
        port: int,
        *,
        timeout: float | None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = _connect_pinned(
            self._pinned_ip,
            self.port,
            self.timeout,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        pinned_ip: str,
        port: int,
        *,
        timeout: float | None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = _connect_pinned(
            self._pinned_ip,
            self.port,
            self.timeout,
        )
        self.sock = self._context.wrap_socket(
            sock,
            server_hostname=self.host,
        )


class HttpClient:
    """Stdlib-only HTTP client with a thin testable seam."""

    def __init__(self, user_agent: str = _USER_AGENT, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self._user_agent = user_agent
        self._timeout = timeout

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        max_redirects: int = _DEFAULT_MAX_REDIRECTS,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        extra_headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Fetch a URL. Follow redirects manually so the caller can inspect
        every hop. Raise ``ApiError`` for unrecoverable failures."""
        chain: list[RedirectHop] = []
        current = url
        seen: set[str] = set()
        validated_ips = _validate_public_url(current)
        for _ in range(max_redirects + 1):
            if current in seen:
                raise ApiError(
                    ErrorCode.UPSTREAM_ERROR,
                    f"Redirect loop detected at {_redact_sensitive_text(current)!r}.",
                    details={
                        "chain": [
                            _redact_sensitive_text(hop.url)
                            for hop in chain
                        ]
                    },
                )
            seen.add(current)
            t0 = time.monotonic()
            pin_token = _PINNED_IP.set(validated_ips[0])
            try:
                status, headers, body = self._http_request_raw(
                    method, current, max_bytes=max_bytes, extra_headers=extra_headers
                )
            finally:
                _PINNED_IP.reset(pin_token)
            elapsed = int((time.monotonic() - t0) * 1000)
            if follow_redirects and 300 <= status < 400 and "location" in headers:
                location = headers["location"]
                resolved = urllib.parse.urljoin(current, location)
                chain.append(RedirectHop(url=current, status=status, location=resolved, elapsed_ms=elapsed))
                validated_ips = _validate_public_url(resolved)
                current = resolved
                continue
            return HttpResponse(
                status=status,
                headers=headers,
                body_bytes=body,
                final_url=current,
                redirect_chain=chain,
            )
        raise ApiError(
            ErrorCode.UPSTREAM_ERROR,
            f"Exceeded max_redirects={max_redirects} starting at {_redact_sensitive_text(url)!r}.",
            details={
                "chain": [
                    _redact_sensitive_text(hop.url)
                    for hop in chain
                ]
            },
        )

    def _http_request_raw(
        self,
        method: str,
        url: str,
        *,
        max_bytes: int,
        extra_headers: dict[str, str] | None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Perform one request using the already validated destination IP."""
        parsed = urllib.parse.urlsplit(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ApiError(
                ErrorCode.INVALID_INPUT,
                f"URL must start with http:// or https://, got {url!r}.",
            )

        pinned_ip = _PINNED_IP.get()
        if pinned_ip is None:
            pinned_ip = _validate_public_url(url)[0]

        port = parsed.port or (
            443 if parsed.scheme == "https" else 80
        )

        target = urllib.parse.urlunsplit(
            ("", "", parsed.path or "/", parsed.query, "")
        )

        headers = {
            "User-Agent": self._user_agent,
            "Accept": "*/*",
        }
        if extra_headers:
            headers.update(extra_headers)

        connection_cls = (
            _PinnedHTTPSConnection
            if parsed.scheme == "https"
            else _PinnedHTTPConnection
        )

        conn = connection_cls(
            parsed.hostname,
            pinned_ip,
            port,
            timeout=self._timeout,
        )

        try:
            conn.request(method, target, headers=headers)
            resp = conn.getresponse()

            response_headers = {
                key.lower(): value
                for key, value in resp.getheaders()
            }

            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                body = body[:max_bytes]

            return resp.status, response_headers, body

        except TimeoutError as exc:
            safe_url = _redact_sensitive_text(url)
            raise ApiError(
                ErrorCode.UPSTREAM_ERROR,
                f"HTTP request to {safe_url!r} timed out after {self._timeout}s.",
            ) from exc

        except (OSError, http.client.HTTPException) as exc:
            safe_url = _redact_sensitive_text(url)
            reason = _redact_sensitive_text(str(exc))
            raise ApiError(
                ErrorCode.UPSTREAM_ERROR,
                f"HTTP request to {safe_url!r} failed: {reason}",
            ) from exc

        finally:
            conn.close()

    @staticmethod
    def _read_response(resp: Any, max_bytes: int) -> tuple[int, dict[str, str], bytes]:
        status = getattr(resp, "status", None) or getattr(resp, "code", 0)
        # urllib gives us a list of (name, value) pairs; lowercase keys.
        headers: dict[str, str] = {}
        for k, v in (resp.headers.items() if hasattr(resp, "headers") else []):
            headers[k.lower()] = v
        body = resp.read(max_bytes + 1) if hasattr(resp, "read") else b""
        if len(body) > max_bytes:
            body = body[:max_bytes]
        return status, headers, body


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disables urllib's automatic redirect handling so we can see every hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def build_http_client() -> HttpClient:
    """Builder used by the server's ``_CLIENT_BUILDERS`` registry. No config
    needed; the HttpClient is fully self-contained."""
    return HttpClient()
