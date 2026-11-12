"""Kanonik JSON untuk hash buku besar (modul murni, tanpa I/O).

Kanonik: JSON dengan kunci terurut, tanpa spasi, UTF-8, string NFC, tanpa angka pecahan (ditolak),
tanpa NUL. Hash stabil lintas proses dan versi pustaka hanya bila aturan ini tidak berubah.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Any

import orjson
from astria_common.errors import AstriaError

FORBIDDEN_KEYS = frozenset({"password", "secret", "token", "api_key", "apikey", "private_key", "session_token"})


class NotCanonical(AstriaError):
    def __init__(self, reason: str) -> None:
        super().__init__("PAYLOAD_TIDAK_KANONIK", reason, 422)


def normalize(value: Any, path: str = "") -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        raise NotCanonical(f"angka pecahan tidak diizinkan ({path or 'payload'})")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        if "\x00" in value:
            raise NotCanonical(f"karakter NUL tidak diizinkan ({path})")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [normalize(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        out = {}
        for key, v in value.items():
            nkey = unicodedata.normalize("NFC", str(key))
            if nkey.lower() in FORBIDDEN_KEYS:
                raise NotCanonical(f"kunci terlarang di payload: {nkey}")
            out[nkey] = normalize(v, f"{path}.{nkey}" if path else nkey)
        return out
    raise NotCanonical(f"tipe tidak didukung: {type(value).__name__}")


def canonical(value: Any) -> bytes:
    return orjson.dumps(normalize(value), option=orjson.OPT_SORT_KEYS)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
