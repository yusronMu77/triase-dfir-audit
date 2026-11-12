"""Hash entri buku besar (modul murni, tanpa I/O).

`entry_hash` = SHA-256 kanonik seluruh field entri kecuali `entry_hash` dan `payload` (diwakili `payload_hash`);
`prev_hash` ikut terhitung sehingga urutan terkunci. Entri pertama memakai `prev_hash` 64 nol.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from astria_audit.chain.canonical import canonical, sha256_hex

GENESIS_PREV = "0" * 64

ENTRY_HASH_FIELDS = (
    "seq",
    "occurred_at",
    "recorded_at",
    "actor",
    "actor_type",
    "action",
    "target_type",
    "target_id",
    "via",
    "idempotency_key",
    "payload_hash",
    "prev_hash",
)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def entry_hash(entry: dict[str, Any]) -> str:
    return sha256_hex(canonical({k: entry[k] for k in ENTRY_HASH_FIELDS}))
