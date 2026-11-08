"""Buku besar audit berantai hash: kanonik, penulis tunggal, dan verifikasi.

Kanonik: JSON dengan kunci terurut, tanpa spasi, UTF-8, string NFC, tanpa angka pecahan (ditolak),
tanpa NUL. `payload_hash` = SHA-256 kanonik payload. `entry_hash` = SHA-256 kanonik seluruh field entri
kecuali `entry_hash` dan `payload` (diwakili `payload_hash`). Entri pertama memakai `prev_hash` 64 nol.

Penulis tunggal: setiap penulisan mengambil `pg_advisory_xact_lock` lalu membaca kepala rantai, jadi
beberapa replika tetap menghasilkan nomor urut tanpa celah.
"""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import UTC, datetime
from typing import Any

import orjson
from astria_common.errors import AstriaError
from astria_contracts.events.audit_record import AuditRecord
from sqlalchemy import BigInteger, Column, DateTime, MetaData, Table, Text, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

GENESIS_PREV = "0" * 64
MAX_PAYLOAD_BYTES = 4096
LOCK_KEY = 0x4153_5452_4941  # "ASTRIA"
FORBIDDEN_KEYS = frozenset({"password", "secret", "token", "api_key", "apikey", "private_key", "session_token"})

metadata = MetaData()
entries = Table(
    "entries",
    metadata,
    Column("seq", BigInteger, primary_key=True, autoincrement=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("recorded_at", DateTime(timezone=True), nullable=False),
    Column("actor", Text, nullable=False),
    Column("actor_type", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("target_type", Text, nullable=False),
    Column("target_id", Text, nullable=False),
    Column("via", Text, nullable=False),
    Column("idempotency_key", Text, nullable=False, unique=True),
    Column("request_hash", Text, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("payload_hash", Text, nullable=False),
    Column("prev_hash", Text, nullable=False),
    Column("entry_hash", Text, nullable=False),
)

# Append-only di tingkat basis data: UPDATE, DELETE, dan TRUNCATE ditolak pemicu.
SETUP_SQL = [
    """
    CREATE OR REPLACE FUNCTION audit_tolak_ubah() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'audit.entries hanya boleh ditambah (%)', TG_OP USING ERRCODE = 'insufficient_privilege';
    END $$
    """,
    "DROP TRIGGER IF EXISTS entries_append_only ON entries",
    "CREATE TRIGGER entries_append_only BEFORE UPDATE OR DELETE ON entries"
    " FOR EACH ROW EXECUTE FUNCTION audit_tolak_ubah()",
    "DROP TRIGGER IF EXISTS entries_no_truncate ON entries",
    "CREATE TRIGGER entries_no_truncate BEFORE TRUNCATE ON entries"
    " FOR EACH STATEMENT EXECUTE FUNCTION audit_tolak_ubah()",
]


class NotCanonical(AstriaError):
    def __init__(self, reason: str) -> None:
        super().__init__("PAYLOAD_TIDAK_KANONIK", reason, 422)


def _normalize(value: Any, path: str = "") -> Any:
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
        return [_normalize(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        out = {}
        for key, v in value.items():
            nkey = unicodedata.normalize("NFC", str(key))
            if nkey.lower() in FORBIDDEN_KEYS:
                raise NotCanonical(f"kunci terlarang di payload: {nkey}")
            out[nkey] = _normalize(v, f"{path}.{nkey}" if path else nkey)
        return out
    raise NotCanonical(f"tipe tidak didukung: {type(value).__name__}")


def canonical(value: Any) -> bytes:
    return orjson.dumps(_normalize(value), option=orjson.OPT_SORT_KEYS)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def entry_hash(entry: dict[str, Any]) -> str:
    fields = {
        k: entry[k]
        for k in (
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
    }
    return sha256_hex(canonical(fields))


def request_fingerprint(record: AuditRecord) -> str:
    data = record.model_dump(mode="json")
    data["occurred_at"] = fmt_ts(record.occurred_at)
    return sha256_hex(canonical(data))


async def write(conn: AsyncConnection, record: AuditRecord) -> tuple[dict[str, Any], bool]:
    """Tulis satu entri di transaksi `conn`. Mengembalikan (entri, duplikat)."""
    payload = _normalize(record.payload)
    raw_payload = canonical(payload)
    if len(raw_payload) > MAX_PAYLOAD_BYTES:
        raise AstriaError("PAYLOAD_TERLALU_BESAR", f"payload melebihi {MAX_PAYLOAD_BYTES} byte", 413)
    fingerprint = request_fingerprint(record)

    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LOCK_KEY})
    existing = (
        (await conn.execute(select(entries).where(entries.c.idempotency_key == record.idempotency_key)))
        .mappings()
        .first()
    )
    if existing is not None:
        if existing["request_hash"] != fingerprint:
            raise AstriaError("PAYLOAD_MISMATCH", "kunci idempoten sama dengan isi berbeda", 409)
        return dict(existing), True

    head = (
        await conn.execute(select(entries.c.seq, entries.c.entry_hash).order_by(entries.c.seq.desc()).limit(1))
    ).first()
    seq = (head.seq + 1) if head else 1
    prev = head.entry_hash if head else GENESIS_PREV
    occurred = record.occurred_at.astimezone(UTC)
    recorded = datetime.now(UTC)
    entry: dict[str, Any] = {
        "seq": seq,
        "occurred_at": fmt_ts(occurred),
        "recorded_at": fmt_ts(recorded),
        "actor": record.actor,
        "actor_type": record.actor_type,
        "action": record.action,
        "target_type": record.target_type,
        "target_id": record.target_id,
        "via": record.via,
        "idempotency_key": record.idempotency_key,
        "payload_hash": sha256_hex(raw_payload),
        "prev_hash": prev,
    }
    entry["entry_hash"] = entry_hash(entry)
    await conn.execute(
        entries.insert().values(
            **(entry | {"occurred_at": occurred, "recorded_at": recorded}),
            request_hash=fingerprint,
            payload=payload,
        )
    )
    return entry | {"payload": payload}, False


def row_to_entry(row: Any) -> dict[str, Any]:
    entry = {k: row[k] for k in entries.c.keys() if k != "request_hash"}
    entry["occurred_at"] = fmt_ts(row["occurred_at"])
    entry["recorded_at"] = fmt_ts(row["recorded_at"])
    return entry


async def verify(conn: AsyncConnection, *, batch: int = 1000) -> dict[str, Any]:
    """Verifikasi seluruh rantai secara bertahap. Berhenti di entri rusak pertama."""
    prev = GENESIS_PREV
    expected_seq = 1
    checked = 0
    last_seq: int | None = None
    while True:
        rows = (
            (
                await conn.execute(
                    select(entries).where(entries.c.seq >= expected_seq).order_by(entries.c.seq).limit(batch)
                )
            )
            .mappings()
            .all()
        )
        if not rows:
            break
        for row in rows:
            entry = row_to_entry(row)
            reason = None
            if entry["seq"] != expected_seq:
                reason = "nomor_urut_berlubang"
            elif entry["prev_hash"] != prev:
                reason = "prev_hash_tidak_cocok"
            elif sha256_hex(canonical(entry["payload"])) != entry["payload_hash"]:
                reason = "payload_hash_tidak_cocok"
            elif entry_hash(entry) != entry["entry_hash"]:
                reason = "entry_hash_tidak_cocok"
            if reason:
                return {
                    "status": "selesai",
                    "from_seq": 1,
                    "to_seq": last_seq,
                    "checked": checked,
                    "ok": False,
                    "first_bad_seq": entry["seq"],
                    "reason": reason,
                }
            prev = entry["entry_hash"]
            last_seq = entry["seq"]
            expected_seq += 1
            checked += 1
    return {
        "status": "selesai",
        "from_seq": 1,
        "to_seq": last_seq,
        "checked": checked,
        "ok": True,
        "first_bad_seq": None,
        "reason": None,
    }
