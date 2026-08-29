"""Sangfor XDR HTTP client: sign + send, no business methods.

TLS verification is on by default. HTTP status and JSON ``code`` are modeled
separately — HTTP 200 is not business success.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from app.adapters.sangfor.signing import (
    SignedRequest,
    load_credentials,
    redact_signing_text,
    resolve_payload,
    sign_request,
)

logger = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r":([A-Za-z][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class SangforHttpResult:
    """Transport vs business outcome are independent fields."""

    http_status: int
    business_code: str | None
    message: str | None
    data: Any
    raw_text: str
    signed: SignedRequest


def apply_path_params(path: str, path_params: Mapping[str, Any] | None) -> str:
    """Replace URI placeholders such as ``:taskId`` even when restfulParam is empty."""
    if not path_params:
        return path
    rewritten = path
    for key, value in path_params.items():
        rewritten = rewritten.replace(f":{key}", str(value))
    leftover = _PLACEHOLDER_RE.findall(rewritten)
    if leftover:
        raise ValueError(f"unreplaced path placeholders: {leftover}")
    return rewritten


def _parse_business(raw_text: str) -> tuple[str | None, str | None, Any]:
    text = raw_text.strip()
    if not text:
        return None, None, None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, None, None
    if not isinstance(payload, dict):
        return None, None, payload
    code = payload.get("code")
    message = payload.get("message")
    return (
        None if code is None else str(code),
        None if message is None else str(message),
        payload.get("data"),
    )


class SangforXdrClient:
    """Generic signed HTTP client. No ``list_incidents`` or other business verbs."""

    def __init__(
        self,
        base_url: str,
        *,
        access_key: str | None = None,
        secret_key: str | None = None,
        auth_code: str | None = None,
        timeout_s: float = 30.0,
        verify: bool = True,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._credentials = load_credentials(
            access_key=access_key,
            secret_key=secret_key,
            auth_code=auth_code,
        )
        self._timeout_s = timeout_s
        self._verify = verify
        self._client = client
        self._owns_client = client is None

    @property
    def tls_verify(self) -> bool:
        return self._verify

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout_s,
                verify=self._verify,
            )
            self._owns_client = True
        return self._client

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        data: str | bytes | None = None,
        headers: Mapping[str, str] | None = None,
        path_params: Mapping[str, Any] | None = None,
        sign_date: str | None = None,
    ) -> SangforHttpResult:
        resolved_path = apply_path_params(path, path_params)
        url = urljoin(self._base_url, resolved_path.lstrip("/"))
        payload = resolve_payload(data=data, json_body=json_body)
        signed = sign_request(
            method=method.upper(),
            url=url,
            credentials=self._credentials,
            params=params,
            payload=payload,
            headers=headers,
            sign_date=sign_date,
        )
        body_bytes = payload.encode("utf-8") if payload else None
        http = await self._http()
        response = await http.request(
            signed.method,
            signed.url,
            params=None if params is None else dict(params),
            content=body_bytes,
            headers=signed.headers,
        )
        raw_text = response.text
        business_code, message, data_field = _parse_business(raw_text)
        logger.info(
            "sangfor http %s %s status=%s business_code=%s",
            signed.method,
            redact_signing_text(resolved_path),
            response.status_code,
            business_code,
        )
        return SangforHttpResult(
            http_status=response.status_code,
            business_code=business_code,
            message=message,
            data=data_field,
            raw_text=raw_text,
            signed=signed,
        )
