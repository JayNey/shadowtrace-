"""Sangfor OpenAPI HMAC-SHA256 signing (Python authCodeDemo contract).

Source of truth: ``挑战杯物料/OpenAPIDocument/python/authCodeDemo/aksk_py3.py``.
Conflicts with Java/Go demos resolve in favor of the Python Demo.

This module does not send HTTP and does not implement business methods.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import logging
import re
import struct
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from app.core.sanitization import REDACTED, redact_sensitive_text

logger = logging.getLogger(__name__)

AUTH_HEADER_KEY = "Authorization"
SDK_HOST_KEY = "sdk-host"
CONTENT_TYPE_KEY = "content-type"
SDK_CONTENT_TYPE_KEY = "sdk-content-type"
DEFAULT_CONTENT_TYPE = "application/json"
SIGN_DATE_KEY = "sign-date"
EXTEND_HEADER = "algorithm=HMAC-SHA256, Access=%s, SignedHeaders=%s, Signature=%s"
TOTAL_STR = "HMAC-SHA256\n%s\n%s"
AUTH_CODE_PARAMS = "%s+%s+%s+%s+%s+%s+%s+%s"
AUTH_CODE_PARAMS_NUM = 14
AES_BLOCK_SIZE = 16
ZERO_IV = bytes(AES_BLOCK_SIZE)

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_INV_SBOX_LIST = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX_LIST[_v] = _i
_INV_SBOX = bytes(_INV_SBOX_LIST)
_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


@dataclass(frozen=True)
class SangforCredentials:
    access_key: str
    secret_key: str


@dataclass(frozen=True)
class SignedRequest:
    method: str
    url: str
    headers: dict[str, str]
    payload: str
    signature: str
    signed_headers: str
    canonical_request: str
    payload_hash: str
    canonical_query: str
    access_key: str


def _xtime(value: int) -> int:
    return ((value << 1) ^ 0x1B) & 0xFF if value & 0x80 else (value << 1) & 0xFF


def _mul(value: int, coeff: int) -> int:
    result = 0
    current = value
    mask = coeff
    while mask:
        if mask & 1:
            result ^= current
        current = _xtime(current)
        mask >>= 1
    return result


def _sub_word(word: int) -> int:
    return (
        (_SBOX[(word >> 24) & 0xFF] << 24)
        | (_SBOX[(word >> 16) & 0xFF] << 16)
        | (_SBOX[(word >> 8) & 0xFF] << 8)
        | _SBOX[word & 0xFF]
    )


def _rot_word(word: int) -> int:
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)


def _expand_key(key: bytes) -> list[bytes]:
    if len(key) != 32:
        raise ValueError("Sangfor auth-code AES key must be 32 bytes (AES-256)")
    n_k = 8
    n_r = 14
    words = [int.from_bytes(key[i : i + 4], "big") for i in range(0, 32, 4)]
    for i in range(n_k, 4 * (n_r + 1)):
        temp = words[i - 1]
        if i % n_k == 0:
            temp = _sub_word(_rot_word(temp)) ^ (_RCON[i // n_k] << 24)
        elif i % n_k == 4:
            temp = _sub_word(temp)
        words.append(words[i - n_k] ^ temp)
    material = b"".join(word.to_bytes(4, "big") for word in words)
    return [material[i : i + 16] for i in range(0, 16 * (n_r + 1), 16)]


def _add_round_key(state: list[int], round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def _sub_bytes(state: list[int], box: bytes) -> None:
    for i in range(16):
        state[i] = box[state[i]]


def _shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _inv_shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def _mix_columns(state: list[int]) -> None:
    for col in range(0, 16, 4):
        a, b, c, d = state[col], state[col + 1], state[col + 2], state[col + 3]
        state[col] = _xtime(a) ^ _xtime(b) ^ b ^ c ^ d
        state[col + 1] = a ^ _xtime(b) ^ _xtime(c) ^ c ^ d
        state[col + 2] = a ^ b ^ _xtime(c) ^ _xtime(d) ^ d
        state[col + 3] = _xtime(a) ^ a ^ b ^ c ^ _xtime(d)


def _inv_mix_columns(state: list[int]) -> None:
    for col in range(0, 16, 4):
        a, b, c, d = state[col], state[col + 1], state[col + 2], state[col + 3]
        state[col] = _mul(a, 14) ^ _mul(b, 11) ^ _mul(c, 13) ^ _mul(d, 9)
        state[col + 1] = _mul(a, 9) ^ _mul(b, 14) ^ _mul(c, 11) ^ _mul(d, 13)
        state[col + 2] = _mul(a, 13) ^ _mul(b, 9) ^ _mul(c, 14) ^ _mul(d, 11)
        state[col + 3] = _mul(a, 11) ^ _mul(b, 13) ^ _mul(c, 9) ^ _mul(d, 14)


def _encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    state = list(block)
    _add_round_key(state, round_keys[0])
    for round_i in range(1, 14):
        _sub_bytes(state, _SBOX)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_i])
    _sub_bytes(state, _SBOX)
    _shift_rows(state)
    _add_round_key(state, round_keys[14])
    return bytes(state)


def _decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    state = list(block)
    _add_round_key(state, round_keys[14])
    for round_i in range(13, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, _INV_SBOX)
        _add_round_key(state, round_keys[round_i])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, _INV_SBOX)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def aes_256_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes = ZERO_IV) -> bytes:
    """AES-256-CBC NoPadding decrypt. IV defaults to 16 zero bytes (Demo)."""
    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("auth-code ciphertext must be a non-empty multiple of 16 bytes")
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("AES IV must be 16 bytes")
    round_keys = _expand_key(key)
    plain = bytearray()
    prev = iv
    for offset in range(0, len(ciphertext), AES_BLOCK_SIZE):
        block = ciphertext[offset : offset + AES_BLOCK_SIZE]
        decrypted = _decrypt_block(block, round_keys)
        plain.extend(a ^ b for a, b in zip(decrypted, prev, strict=True))
        prev = block
    return bytes(plain)


def aes_256_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = ZERO_IV) -> bytes:
    """AES-256-CBC NoPadding encrypt (test-vector construction only)."""
    if len(plaintext) == 0 or len(plaintext) % AES_BLOCK_SIZE != 0:
        raise ValueError("plaintext must be a non-empty multiple of 16 bytes")
    round_keys = _expand_key(key)
    out = bytearray()
    prev = iv
    for offset in range(0, len(plaintext), AES_BLOCK_SIZE):
        block = plaintext[offset : offset + AES_BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, prev, strict=True))
        encrypted = _encrypt_block(xored, round_keys)
        out.extend(encrypted)
        prev = encrypted
    return bytes(out)


def _sha256_hex_upper(data: bytes) -> str:
    return binascii.hexlify(hashlib.sha256(data).digest()).decode("ascii").upper()


def _hmac_sha256_hex(secret_key: str, data: str) -> str:
    digest = hmac.new(secret_key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).digest()
    return binascii.hexlify(digest).decode("ascii").upper()


def _remove_spaces(payload: bytearray) -> bytes:
    kept = bytearray()
    for byte in payload:
        if byte != 0x20:
            kept.append(byte)
    return bytes(kept)


def payload_hash(payload: str) -> str:
    """Demo payload hash: signed-byte sort, strip 0x20, SHA-256 uppercase hex."""
    encoded = payload.encode("utf-8")
    signed = [struct.unpack("b", bytes([byte]))[0] for byte in encoded]
    signed.sort()
    ordered = bytearray(byte & 0xFF for byte in signed)
    return _sha256_hex_upper(_remove_spaces(ordered))


def query_canonical(params: Mapping[str, Any] | None) -> str:
    """Sort keys, urlencode, then restore ``%3D`` → ``=``. ``None`` equals ``{}``."""
    items = {} if params is None else dict(params)
    sorted_items = sorted(items.items(), key=lambda item: str(item[0]))
    return urllib.parse.urlencode(sorted_items).replace("%3D", "=")


def canonical_path(url: str) -> str:
    relative_path = urlparse(url).path
    if not relative_path.endswith("/"):
        relative_path += "/"
    return urllib.parse.quote(relative_path, encoding="utf-8")


def empty_json_object_is_no_payload(json_body: Any) -> bool:
    return json_body == {}


def resolve_payload(*, data: str | bytes | None = None, json_body: Any = None) -> str:
    """Match Demo: ``{}`` JSON becomes no payload; HTTP still sends this string."""
    if data is not None and data != b"" and data != "":
        if isinstance(data, bytes):
            return data.decode("utf-8")
        return str(data)
    if json_body is None or empty_json_object_is_no_payload(json_body):
        return ""
    if isinstance(json_body, str):
        return json_body
    return json.dumps(json_body, ensure_ascii=False)


def _header_check(
    headers: Mapping[str, str] | None,
    host: str,
    *,
    sign_date: str | None,
) -> tuple[dict[str, str], str]:
    checked = dict(headers or {})
    if SDK_HOST_KEY not in checked:
        checked[SDK_HOST_KEY] = host
    if CONTENT_TYPE_KEY not in checked:
        checked[SDK_CONTENT_TYPE_KEY] = DEFAULT_CONTENT_TYPE
    else:
        checked[SDK_CONTENT_TYPE_KEY] = checked[CONTENT_TYPE_KEY]
    if SIGN_DATE_KEY not in checked:
        resolved = sign_date or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        checked[SIGN_DATE_KEY] = resolved
    else:
        resolved = checked[SIGN_DATE_KEY]
    return checked, resolved


def _sign_header_handler(headers: Mapping[str, str]) -> tuple[str, str]:
    ordered = sorted(headers.items(), key=lambda item: item[0].lower())
    header_builder: list[str] = []
    sign_header_builder: list[str] = []
    for key, value in ordered:
        header_builder.append(f"{key}:{value}\n")
        sign_header_builder.append(f"{key};")
    sign_header_str = "".join(sign_header_builder)
    if sign_header_str:
        sign_header_str = sign_header_str[:-1]
    return "".join(header_builder), sign_header_str


def decode_auth_code(auth_code: str) -> SangforCredentials:
    """Decode linkage authCode. AES-CBC IV is 16 zero bytes; ciphertext has no IV prefix."""
    try:
        decoded = binascii.unhexlify(auth_code)
    except binascii.Error as exc:
        raise ValueError("auth code is not valid hex") from exc
    builders = decoded.decode("utf-8").split("|")
    if len(builders) != AUTH_CODE_PARAMS_NUM:
        raise ValueError("auth code decode error")
    aes_secret = hashlib.sha256(
        (
            AUTH_CODE_PARAMS
            % (
                builders[0],
                builders[1],
                builders[2],
                builders[3],
                builders[4],
                builders[5],
                builders[6],
                builders[11],
            )
        ).encode("utf-8")
    ).digest()
    ak_ct = bytes.fromhex(builders[9])
    sk_ct = bytes.fromhex(builders[10])
    if len(ak_ct) < AES_BLOCK_SIZE or (len(ak_ct) % AES_BLOCK_SIZE) != 0:
        raise ValueError("auth-code AK ciphertext is not AES blocks")
    ak = aes_256_cbc_decrypt(ak_ct, aes_secret, ZERO_IV).decode("utf-8").strip()
    sk = aes_256_cbc_decrypt(sk_ct, aes_secret, ZERO_IV).decode("utf-8").strip()
    return SangforCredentials(access_key=ak, secret_key=sk)


def load_credentials(
    *,
    access_key: str | None = None,
    secret_key: str | None = None,
    auth_code: str | None = None,
) -> SangforCredentials:
    if access_key and secret_key:
        return SangforCredentials(access_key=access_key, secret_key=secret_key)
    if auth_code:
        return decode_auth_code(auth_code)
    raise ValueError("signature init error")


_EXTRA_SECRET_RE = re.compile(
    r"(?P<prefix>\b(?:auth[_-]?code|secret[_-]?key|linkage[_-]?code)\b[\"']?\s*[:=]\s*)"
    r"(?P<secret>\"[^\"]*\"|'[^']*'|[^\s,;&}]+)",
    re.IGNORECASE,
)
_HMAC_AUTH_RE = re.compile(
    r"(?:,\s*)?(?:algorithm=HMAC-SHA256,\s*)?Access=[A-Za-z0-9._-]+,\s*"
    r"SignedHeaders=[^,\r\n]+,\s*Signature=[A-Fa-f0-9]+",
    re.IGNORECASE,
)


def redact_signing_text(value: str) -> str:
    """Redact SK / linkage codes / Authorization from logs."""
    cleaned = redact_sensitive_text(value)
    cleaned = _EXTRA_SECRET_RE.sub(lambda match: f"{match.group('prefix')}{REDACTED}", cleaned)
    return _HMAC_AUTH_RE.sub(f"algorithm=HMAC-SHA256, Access={REDACTED}", cleaned)


def sign_request(
    *,
    method: str,
    url: str,
    credentials: SangforCredentials,
    params: Mapping[str, Any] | None = None,
    payload: str = "",
    headers: Mapping[str, str] | None = None,
    sign_date: str | None = None,
) -> SignedRequest:
    """Return signed headers. Caller must send ``payload`` unchanged."""
    if not credentials.access_key or not credentials.secret_key:
        raise ValueError("ak sk can't be blank")
    if not url or not method:
        raise ValueError(
            "params illegal,params can't be nil or blank except payload or query string"
        )

    host = urlparse(url).netloc
    checked, resolved_date = _header_check(headers, host, sign_date=sign_date)
    header_str, signed_headers = _sign_header_handler(checked)
    canonical_query = query_canonical(params)
    body_hash = payload_hash(payload)
    canonical = "".join(
        (
            method,
            "\n",
            canonical_path(url),
            "\n",
            canonical_query,
            "\n",
            header_str,
            signed_headers,
            "\n",
            body_hash,
        )
    )
    hashed_canonical = _sha256_hex_upper(canonical.encode("utf-8"))
    total = TOTAL_STR % (resolved_date, hashed_canonical)
    signature = _hmac_sha256_hex(credentials.secret_key, total)
    out_headers = dict(checked)
    out_headers[AUTH_HEADER_KEY] = EXTEND_HEADER % (
        credentials.access_key,
        signed_headers,
        signature,
    )
    logger.debug(
        "sangfor signed %s %s signed_headers=%s",
        method,
        redact_signing_text(url),
        signed_headers,
    )
    return SignedRequest(
        method=method,
        url=url,
        headers=out_headers,
        payload=payload,
        signature=signature,
        signed_headers=signed_headers,
        canonical_request=canonical,
        payload_hash=body_hash,
        canonical_query=canonical_query,
        access_key=credentials.access_key,
    )
