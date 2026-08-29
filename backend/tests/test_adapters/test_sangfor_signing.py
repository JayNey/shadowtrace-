"""Sangfor signing + HTTP client gates (alignment plan Layer 1)."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest

from app.adapters.sangfor.client import SangforXdrClient, apply_path_params
from app.adapters.sangfor.signing import (
    AUTH_HEADER_KEY,
    ZERO_IV,
    SangforCredentials,
    _encrypt_block,
    _expand_key,
    aes_256_cbc_decrypt,
    canonical_path,
    decode_auth_code,
    payload_hash,
    query_canonical,
    redact_signing_text,
    resolve_payload,
    sign_request,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VECTORS = json.loads(
    (_REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "signing_vectors.json").read_text(
        encoding="utf-8"
    )
)


def _creds() -> SangforCredentials:
    return SangforCredentials(_VECTORS["ak"], _VECTORS["sk"])


def _sign(
    *,
    method: str,
    url: str,
    params: dict[str, Any] | None,
    payload: str,
) -> str:
    signed = sign_request(
        method=method,
        url=url,
        credentials=_creds(),
        params=params,
        payload=payload,
        headers={"content-type": "application/json"},
        sign_date=_VECTORS["sign_date"],
    )
    return signed.signature


def test_aes256_nist_ecb_block() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    expect = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    cipher = _encrypt_block(plain, _expand_key(key))
    assert cipher == expect
    assert aes_256_cbc_decrypt(cipher, key, ZERO_IV) == plain


def test_auth_code_zero_iv_decrypts_to_vector() -> None:
    blob = _VECTORS["auth_code"]
    assert blob["iv"] == "00" * 16
    assert not blob["ak_ciphertext_hex"].startswith("00" * 16)
    creds = decode_auth_code(blob["hex"])
    assert creds.access_key == blob["expected_ak"]
    assert creds.secret_key == blob["expected_sk"]


def test_payload_spaces_and_key_order_share_hash() -> None:
    case = _VECTORS["cases"]["post_json_spaces_and_key_order"]
    assert case["a"]["payload_hash"] == case["b"]["payload_hash"] == case["c"]["payload_hash"]
    assert payload_hash(case["a"]["payload"]) == case["a"]["payload_hash"]
    assert (
        _sign(
            method="POST",
            url=case["a"]["url"],
            params={},
            payload=case["a"]["payload"],
        )
        == case["a"]["signature"]
    )
    assert (
        _sign(
            method="POST",
            url=case["b"]["url"],
            params={},
            payload=case["b"]["payload"],
        )
        == case["b"]["signature"]
    )


def test_query_percent3d_restored_to_equals() -> None:
    case = _VECTORS["cases"]["query_equals_percent3d"]
    canonical = query_canonical(case["params"])
    assert canonical == "filter=a=b&z=1"
    encoded = urlencode(sorted(case["params"].items()))
    assert "%3D" in encoded
    assert canonical == encoded.replace("%3D", "=")
    assert case["canonical_query"] == canonical
    assert (
        _sign(
            method=case["method"],
            url=case["url"],
            params=case["params"],
            payload=case["payload"],
        )
        == case["signature"]
    )


def test_params_none_matches_empty_dict() -> None:
    case = _VECTORS["cases"]["params_none_vs_empty"]
    assert query_canonical(None) == ""
    assert query_canonical({}) == ""
    assert case["none"]["signature"] == case["empty"]["signature"]
    assert (
        _sign(method="POST", url=case["none"]["url"], params=None, payload="")
        == (case["none"]["signature"])
    )


def test_empty_json_object_is_no_payload_but_literal_braces_differ() -> None:
    case = _VECTORS["cases"]["empty_json_object_vs_payload"]
    assert resolve_payload(json_body={}) == ""
    assert resolve_payload(json_body=None) == ""
    assert resolve_payload(data="{}") == "{}"
    assert case["no_payload"]["signature"] == case["empty_object"]["signature"]
    assert case["literal_braces"]["signature"] != case["no_payload"]["signature"]
    assert payload_hash("{}") == case["literal_braces"]["payload_hash"]
    assert payload_hash("") == case["no_payload"]["payload_hash"]


def test_trailing_slash_matches_demo_canonical_path() -> None:
    case = _VECTORS["cases"]["path_trailing_slash"]
    assert canonical_path(case["without"]["url"]) == canonical_path(case["with"]["url"])
    assert case["without"]["signature"] == case["with"]["signature"]
    assert (
        _sign(
            method="POST",
            url=case["without"]["url"],
            params={},
            payload="",
        )
        == case["without"]["signature"]
    )


def test_authorization_uses_python_header_names() -> None:
    signed = sign_request(
        method="POST",
        url="https://xdr.example.com/api/xdr/v1/incidents/list",
        credentials=_creds(),
        params={},
        payload="",
        headers={"content-type": "application/json"},
        sign_date=_VECTORS["sign_date"],
    )
    assert AUTH_HEADER_KEY in signed.headers
    assert "authorization" not in signed.headers
    assert signed.headers[AUTH_HEADER_KEY].startswith("algorithm=HMAC-SHA256, Access=")
    assert "Algorithm=" not in signed.headers[AUTH_HEADER_KEY]
    assert "sdk-host" in signed.headers
    assert "sdk-content-type" in signed.headers
    assert signed.headers["sdk-content-type"] == "application/json"
    assert "content-type" in signed.signed_headers
    assert "sdk-content-type" in signed.signed_headers


def test_go_cross_signature_hex_matches_python() -> None:
    cross = _VECTORS["go_cross"]
    signature = _sign(
        method=cross["method"],
        url=cross["url"],
        params=cross["params"],
        payload=cross["payload"],
    )
    assert signature == cross["signature"]
    assert signature == signature.upper()


def test_tampered_body_changes_signature() -> None:
    url = "https://xdr.example.com/api/xdr/v1/incidents/dealstatus"
    original = '{"dealStatus": 10}'
    tampered = '{"dealStatus": 70}'
    assert _sign(method="POST", url=url, params={}, payload=original) != _sign(
        method="POST", url=url, params={}, payload=tampered
    )


def test_payload_hash_is_not_raw_sha256() -> None:
    body = '{"uuIds": ["incident-1"], "dealStatus": 10}'
    raw = hashlib.sha256(body.encode("utf-8")).hexdigest().upper()
    assert payload_hash(body) != raw


def test_apply_task_id_placeholder() -> None:
    assert (
        apply_path_params("/api/xdr/v1/responses/virusscantask/:taskId", {"taskId": "abc"})
        == "/api/xdr/v1/responses/virusscantask/abc"
    )


def test_client_has_no_business_methods() -> None:
    assert not hasattr(SangforXdrClient, "list_incidents")
    assert not hasattr(SangforXdrClient, "list_alerts")


def test_tls_verify_defaults_true_without_injected_client() -> None:
    client = SangforXdrClient(
        "https://xdr.example.com",
        access_key=_VECTORS["ak"],
        secret_key=_VECTORS["sk"],
    )
    assert client.tls_verify is True


def test_redact_blocks_secret_key_auth_code_and_authorization() -> None:
    blob = (
        f"auth_code={_VECTORS['auth_code']['hex']} "
        f"secret_key={_VECTORS['sk']} "
        "Authorization: algorithm=HMAC-SHA256, Access=test-ak-01xxxxxx, "
        "SignedHeaders=content-type, Signature=DEADBEEFCAFE"
    )
    cleaned = redact_signing_text(blob)
    assert _VECTORS["sk"] not in cleaned
    assert _VECTORS["auth_code"]["hex"] not in cleaned
    assert "DEADBEEFCAFE" not in cleaned
    assert "[REDACTED]" in cleaned


def test_demo_payload_transform_recompute() -> None:
    """Independent copy of Demo payload sort+strip, not raw SHA-256."""
    payload = '{ "b": 1, "a": 2 }'
    encoded = payload.encode("utf-8")
    signed = [struct.unpack("b", bytes([byte]))[0] for byte in encoded]
    signed.sort()
    ordered = bytearray(byte & 0xFF for byte in signed)
    stripped = bytes(byte for byte in ordered if byte != 0x20)
    demo_hash = hashlib.sha256(stripped).hexdigest().upper()
    assert demo_hash == payload_hash(payload)
    assert demo_hash == _VECTORS["cases"]["post_json_spaces_and_key_order"]["a"]["payload_hash"]


@pytest.mark.asyncio
async def test_client_default_tls_verify_and_sends_original_body() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content"] = request.content
        captured["headers"] = dict(request.headers)
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            json={"code": "InvalidParameter", "message": "bad", "data": None},
        )

    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="https://xdr.example.com")
    client = SangforXdrClient(
        "https://xdr.example.com",
        access_key=_VECTORS["ak"],
        secret_key=_VECTORS["sk"],
        client=http,
    )
    assert client.tls_verify is True
    body = '{"b": 1, "a": 2}'
    result = await client.request(
        "POST",
        "/api/xdr/v1/incidents/list",
        json_body=body,
        headers={"content-type": "application/json"},
        sign_date=_VECTORS["sign_date"],
        params=None,
    )
    assert captured["content"] == body.encode("utf-8")
    assert result.signed.payload == body
    assert result.http_status == 200
    assert result.business_code == "InvalidParameter"
    assert result.business_code != "Success"
    auth = captured["headers"].get("authorization") or captured["headers"].get("Authorization")
    assert auth and auth.startswith("algorithm=HMAC-SHA256")
    assert _VECTORS["sk"] not in json.dumps(captured["headers"])
    await client.aclose()


@pytest.mark.asyncio
async def test_client_replaces_task_id_and_empty_object_sends_no_body() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content"] = request.content
        captured["path"] = request.url.path
        return httpx.Response(200, json={"code": "", "message": "ok", "data": {"taskId": "t1"}})

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    client = SangforXdrClient(
        "https://xdr.example.com",
        access_key=_VECTORS["ak"],
        secret_key=_VECTORS["sk"],
        client=http,
        verify=True,
    )
    result = await client.request(
        "GET",
        "/api/xdr/v1/responses/virusscantask/:taskId",
        path_params={"taskId": "626664a025d603db019fd84c"},
        json_body={},
        params={},
        sign_date=_VECTORS["sign_date"],
    )
    assert captured["path"].endswith("/api/xdr/v1/responses/virusscantask/626664a025d603db019fd84c")
    assert captured["content"] in {b"", None} or captured["content"] == b""
    assert result.signed.payload == ""
    assert result.business_code == ""
    await client.aclose()
