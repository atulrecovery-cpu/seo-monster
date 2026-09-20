from __future__ import annotations

import io

import pytest

from seo_mcp.clients._response import (
    read_json_response,
    read_limited_text,
)
from seo_mcp.clients.errors import ApiError
from seo_mcp.errors import ErrorCode


def test_read_json_response_accepts_bounded_body():
    response = io.BytesIO(b'{"ok": true}')

    assert read_json_response(
        response,
        service="Test",
        max_bytes=100,
    ) == {"ok": True}


def test_read_json_response_rejects_oversized_body():
    response = io.BytesIO(b"x" * 11)

    with pytest.raises(ApiError) as exc_info:
        read_json_response(
            response,
            service="Test",
            max_bytes=10,
        )

    assert exc_info.value.code == ErrorCode.UPSTREAM_ERROR
    assert "larger than 10 bytes" in exc_info.value.message


def test_read_limited_text_rejects_oversized_error_body():
    response = io.BytesIO(b"x" * 11)

    with pytest.raises(ApiError) as exc_info:
        read_limited_text(
            response,
            service="Test",
            max_bytes=10,
        )

    assert exc_info.value.code == ErrorCode.UPSTREAM_ERROR
