"""Bounded response readers for urllib-based vendor clients."""

from __future__ import annotations

import json
from typing import Any

from ..errors import ErrorCode
from .errors import ApiError

MAX_RESPONSE_BYTES = 10 * 1024 * 1024


def read_limited_bytes(
    response: Any,
    *,
    service: str,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> bytes:
    """Read at most ``max_bytes`` from an upstream response."""
    body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ApiError(
            ErrorCode.UPSTREAM_ERROR,
            f"{service} returned a response larger than {max_bytes} bytes.",
        )
    return body


def read_limited_text(
    response: Any,
    *,
    service: str,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> str:
    return read_limited_bytes(
        response,
        service=service,
        max_bytes=max_bytes,
    ).decode("utf-8", errors="replace")


def read_json_response(
    response: Any,
    *,
    service: str,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> Any:
    return json.loads(
        read_limited_bytes(
            response,
            service=service,
            max_bytes=max_bytes,
        )
    )
