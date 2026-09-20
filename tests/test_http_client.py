"""Tests for the generic HttpClient. The single seam is
``HttpClient._http_request_raw``; we monkeypatch it to return canned
(status, headers, body) tuples without touching urllib."""

from __future__ import annotations

import pytest

from seo_mcp.clients.errors import ApiError
from seo_mcp.clients.http import HttpClient, build_http_client
from seo_mcp.errors import ErrorCode


def _stub(responses):
    """Return a fake _http_request_raw that pops one canned response per call.

    Each canned response is (status, headers_dict, body_bytes). Call records
    appended to ``calls``."""
    calls: list[tuple[str, str]] = []
    queue = list(responses)

    def fake(method, url, *, max_bytes, extra_headers):
        calls.append((method, url))
        if not queue:
            raise AssertionError(f"unexpected extra call: {method} {url}")
        return queue.pop(0)

    return fake, calls


def test_build_returns_client():
    assert isinstance(build_http_client(), HttpClient)


def test_fetch_rejects_non_http_url():
    c = HttpClient()
    with pytest.raises(ApiError) as ei:
        c.fetch("file:///etc/passwd")
    assert ei.value.code == ErrorCode.INVALID_INPUT


def test_fetch_returns_terminal_response():
    c = HttpClient()
    fake, calls = _stub([(200, {"content-type": "text/html; charset=utf-8"}, b"<html><body>hi</body></html>")])
    c._http_request_raw = fake
    resp = c.fetch("https://example.com/")
    assert resp.status == 200
    assert resp.final_url == "https://example.com/"
    assert resp.body_text.startswith("<html>")
    assert resp.redirect_chain == []
    assert calls == [("GET", "https://example.com/")]


def test_fetch_follows_redirect_and_records_chain():
    c = HttpClient()
    fake, calls = _stub([
        (301, {"location": "/new"}, b""),
        (200, {"content-type": "text/html"}, b"final"),
    ])
    c._http_request_raw = fake
    resp = c.fetch("https://example.com/old")
    assert resp.status == 200
    assert resp.final_url == "https://example.com/new"
    assert len(resp.redirect_chain) == 1
    assert resp.redirect_chain[0].status == 301
    assert resp.redirect_chain[0].location == "https://example.com/new"
    assert [c[1] for c in calls] == ["https://example.com/old", "https://example.com/new"]


def test_fetch_no_follow_returns_redirect():
    c = HttpClient()
    fake, _ = _stub([(301, {"location": "/new"}, b"")])
    c._http_request_raw = fake
    resp = c.fetch("https://example.com/", follow_redirects=False)
    assert resp.status == 301
    assert resp.redirect_chain == []


def test_fetch_detects_redirect_loop():
    c = HttpClient()
    fake, _ = _stub([
        (302, {"location": "https://example.com/a"}, b""),
        (302, {"location": "https://example.com/a"}, b""),
    ])
    c._http_request_raw = fake
    with pytest.raises(ApiError) as ei:
        c.fetch("https://example.com/a")
    assert ei.value.code == ErrorCode.UPSTREAM_ERROR
    assert "loop" in ei.value.message.lower()


def test_fetch_caps_redirect_chain():
    c = HttpClient()
    fake, _ = _stub([
        (301, {"location": f"https://example.com/{i+1}"}, b"") for i in range(20)
    ])
    c._http_request_raw = fake
    with pytest.raises(ApiError) as ei:
        c.fetch("https://example.com/0", max_redirects=3)
    assert ei.value.code == ErrorCode.UPSTREAM_ERROR
    assert "max_redirects" in ei.value.message


def test_body_text_decodes_with_declared_charset():
    c = HttpClient()
    fake, _ = _stub([(200, {"content-type": "text/html; charset=iso-8859-1"}, b"caf\xe9")])
    c._http_request_raw = fake
    resp = c.fetch("https://example.com/")
    assert resp.body_text == "café"


def test_fetch_rejects_loopback_ip_before_request():
    c = HttpClient()

    def should_not_run(*args, **kwargs):
        raise AssertionError("HTTP request must not run for a loopback target")

    c._http_request_raw = should_not_run

    with pytest.raises(ApiError) as ei:
        c.fetch("http://127.0.0.1/admin")

    assert ei.value.code == ErrorCode.INVALID_INPUT


def test_fetch_rejects_hostname_resolving_to_private_ip(monkeypatch):
    monkeypatch.setattr("seo_mcp.clients.http.socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("10.0.0.7", 0))])
    c = HttpClient()

    def should_not_run(*args, **kwargs):
        raise AssertionError("HTTP request must not run for a private DNS target")

    c._http_request_raw = should_not_run

    with pytest.raises(ApiError) as ei:
        c.fetch("https://private.example/")

    assert ei.value.code == ErrorCode.INVALID_INPUT

def test_fetch_rejects_redirect_to_private_ip(monkeypatch):
    monkeypatch.setattr(
        "seo_mcp.clients.http.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )

    c = HttpClient()
    calls = []

    def fake_request(method, url, *, max_bytes, extra_headers):
        calls.append(url)
        return 302, {"location": "http://127.0.0.1/admin"}, b""

    c._http_request_raw = fake_request

    with pytest.raises(ApiError) as ei:
        c.fetch("https://example.com/")

    assert ei.value.code == ErrorCode.INVALID_INPUT
    assert calls == ["https://example.com/"]


def test_transport_must_pin_validated_dns_address(monkeypatch):
    """The transport must use the IP validated by the SSRF check."""
    dns_calls = []
    pinned_connections = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        dns_calls.append((host, port))
        if len(dns_calls) == 1:
            return [(2, 1, 6, "", ("93.184.216.34", port))]
        return [(2, 1, 6, "", ("10.0.0.7", port))]

    def fake_connect_pinned(ip, port, timeout):
        pinned_connections.append((ip, port))
        raise OSError("test connection stopped")

    monkeypatch.setattr(
        "seo_mcp.clients.http.socket.getaddrinfo",
        fake_getaddrinfo,
    )
    monkeypatch.setattr(
        "seo_mcp.clients.http._connect_pinned",
        fake_connect_pinned,
    )

    client = HttpClient()

    with pytest.raises(Exception):
        client.fetch("http://rebind.example/")

    assert len(dns_calls) == 1
    assert pinned_connections == [("93.184.216.34", 80)]

def test_http_client_sets_user_agent(monkeypatch):
    captured = {}

    class _Resp:
        status = 200

        def getheaders(self):
            return []

        def read(self, n=-1):
            return b"ok"

    class _Connection:
        def __init__(self, host, pinned_ip, port, *, timeout):
            captured["host"] = host
            captured["pinned_ip"] = pinned_ip
            captured["port"] = port

        def request(self, method, target, headers):
            captured["user_agent"] = headers["User-Agent"]

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(
        "seo_mcp.clients.http._PinnedHTTPConnection",
        _Connection,
    )

    c = HttpClient(user_agent="SEOMonster/test")
    response = c.fetch("http://93.184.216.34/")

    assert response.status == 200
    assert captured["user_agent"] == "SEOMonster/test"
    assert captured["pinned_ip"] == "93.184.216.34"

def test_transport_error_redacts_credentials_in_url(monkeypatch):
    secret = "SUPER_SECRET_HTTP_TOKEN"
    url = f"https://example.com/page?token={secret}"
    client = HttpClient()

    class _Connection:
        def __init__(self, host, pinned_ip, port, *, timeout):
            pass

        def request(self, *args, **kwargs):
            raise OSError(f"connection failed for {url}")

        def close(self):
            pass

    monkeypatch.setattr(
        "seo_mcp.clients.http._validate_public_url",
        lambda url: ["93.184.216.34"],
    )
    monkeypatch.setattr(
        "seo_mcp.clients.http._PinnedHTTPSConnection",
        _Connection,
    )

    with pytest.raises(ApiError) as exc_info:
        client._http_request_raw(
            "GET",
            url,
            max_bytes=1024,
            extra_headers=None,
        )

    rendered = str(exc_info.value)
    assert secret not in rendered
    assert "[REDACTED]" in rendered

def test_redirect_loop_error_redacts_credentials(monkeypatch):
    secret = "SUPER_SECRET_REDIRECT_TOKEN"
    url = f"https://example.com/page?token={secret}"
    client = HttpClient()

    def fake_request(method, current, *, max_bytes, extra_headers):
        return 302, {"location": url}, b""

    monkeypatch.setattr(client, "_http_request_raw", fake_request)

    with pytest.raises(ApiError) as exc_info:
        client.fetch(url)

    rendered = str(exc_info.value)
    assert secret not in rendered
    assert "[REDACTED]" in rendered

def test_max_redirects_error_redacts_credentials(monkeypatch):
    secret = "SUPER_SECRET_MAX_REDIRECT_TOKEN"
    url = f"https://example.com/start?token={secret}"
    client = HttpClient()

    def fake_request(method, current, *, max_bytes, extra_headers):
        return 302, {"location": "/next"}, b""

    monkeypatch.setattr(client, "_http_request_raw", fake_request)

    with pytest.raises(ApiError) as exc_info:
        client.fetch(url, max_redirects=0)

    rendered = str(exc_info.value)
    assert secret not in rendered
    assert "[REDACTED]" in rendered

def test_timeout_error_redacts_credentials_in_url(monkeypatch):
    secret = "SUPER_SECRET_TIMEOUT_TOKEN"
    url = f"https://example.com/page?token={secret}"
    client = HttpClient()

    class _Connection:
        def __init__(self, host, pinned_ip, port, *, timeout):
            pass

        def request(self, *args, **kwargs):
            raise TimeoutError("timed out")

        def close(self):
            pass

    monkeypatch.setattr(
        "seo_mcp.clients.http._validate_public_url",
        lambda url: ["93.184.216.34"],
    )
    monkeypatch.setattr(
        "seo_mcp.clients.http._PinnedHTTPSConnection",
        _Connection,
    )

    with pytest.raises(ApiError) as exc_info:
        client._http_request_raw(
            "GET",
            url,
            max_bytes=1024,
            extra_headers=None,
        )

    rendered = str(exc_info.value)
    assert secret not in rendered
    assert "[REDACTED]" in rendered
