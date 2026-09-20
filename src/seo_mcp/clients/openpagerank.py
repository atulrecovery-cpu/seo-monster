"""Open PageRank (DomCop) client (roadmap F6) over stdlib urllib.

The free default backlink-authority proxy: domain rank 0-10 derived from Common
Crawl, refreshed quarterly. Coarse on purpose -- used to WIDEN/narrow a band,
never to mint a precise number (design doc §0.2 / §5 C1). Free API key via
``API-OPR`` header. Network seam ``_raw_request`` for test injection.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ..config import Config
from ..errors import ErrorCode
from ._response import read_json_response, read_limited_text
from .errors import ApiError, _redact_sensitive_text, map_http_status

API_BASE = "https://openpagerank.com/api/v1.0/getPageRank"
_TIMEOUT_SECONDS = 20
_MAX_PER_CALL = 100  # Open PageRank caps domains[] per request


class OpenPageRankClient:
    def __init__(self, api_key: str) -> None:
        self._key = api_key

    def _raw_request(self, domains: list[str]) -> dict[str, Any]:
        query = "&".join(f"domains[]={urllib.parse.quote(d)}" for d in domains)
        request = urllib.request.Request(f"{API_BASE}?{query}", method="GET")
        request.add_header("API-OPR", self._key)
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as resp:
                return read_json_response(resp, service="OpenPageRank")
        except urllib.error.HTTPError as exc:
            body_text = read_limited_text(exc, service="OpenPageRank")
            raise map_http_status(exc.code, body_text, service="OpenPageRank") from exc
        except urllib.error.URLError as exc:
            reason = _redact_sensitive_text(str(exc.reason))
            if self._key:
                reason = reason.replace(self._key, "[REDACTED]")
            raise ApiError(
                ErrorCode.UPSTREAM_ERROR,
                f"OpenPageRank request failed: {reason}",
            ) from exc

    def domain_rank(self, domains: list[str]) -> dict[str, float]:
        """Return ``{domain: page_rank_decimal}`` for the (deduped) domains."""
        uniq = list(dict.fromkeys(d for d in domains if d))[:_MAX_PER_CALL]
        if not uniq:
            return {}
        payload = self._raw_request(uniq)
        out: dict[str, float] = {}
        for r in payload.get("response") or []:
            d = r.get("domain")
            pr = r.get("page_rank_decimal")
            if d is not None and pr is not None:
                try:
                    out[d] = float(pr)
                except (TypeError, ValueError):
                    continue
        return out

    def probe(self) -> bool:
        self.domain_rank(["example.com"])
        return True


def build_openpagerank_client(config: Config) -> OpenPageRankClient | None:
    key = getattr(config, "openpagerank_key", None)
    if not key:
        return None
    return OpenPageRankClient(key)
