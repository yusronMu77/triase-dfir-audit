"""Pembuat rantai valid tanpa basis data, untuk uji murni dan CLI."""

from __future__ import annotations

from typing import Any

import orjson

from astria_audit.chain.canonical import canonical, sha256_hex
from astria_audit.chain.hashing import GENESIS_PREV, entry_hash


def build_chain(count: int, *, start_seq: int = 1, prev_hash: str = GENESIS_PREV) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    prev = prev_hash
    for i in range(count):
        seq = start_seq + i
        payload = {"n": seq, "nama": "Ärsip é", "daftar": [True, None, "x"]}
        entry: dict[str, Any] = {
            "seq": seq,
            "occurred_at": f"2026-11-12T00:00:{seq % 60:02d}.000001Z",
            "recorded_at": f"2026-11-12T00:00:{seq % 60:02d}.000002Z",
            "actor": f"usr_{seq % 3}",
            "actor_type": "user",
            "action": "ticket.claimed" if seq % 2 else "ticket.closed",
            "target_type": "ticket",
            "target_id": f"IC-{seq}",
            "via": "ui",
            "idempotency_key": f"k-{seq}",
            "payload_hash": sha256_hex(canonical(payload)),
            "prev_hash": prev,
        }
        entry["entry_hash"] = entry_hash(entry)
        entry["payload"] = payload
        entries.append(entry)
        prev = entry["entry_hash"]
    return entries


def to_lines(entries: list[dict[str, Any]]) -> list[bytes]:
    return [orjson.dumps(e, option=orjson.OPT_SORT_KEYS) + b"\n" for e in entries]
