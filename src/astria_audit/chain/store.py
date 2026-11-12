"""Penyimpanan buku besar: tabel, penulis tunggal, baca, verifikasi rentang, jangkar, dan tugas verifikasi.

Penulis tunggal: setiap penulisan mengambil `pg_advisory_xact_lock` lalu membaca kepala rantai, jadi
beberapa replika tetap menghasilkan nomor urut tanpa celah. Logika murni (kanonik, hash, verifier) ada di
modul saudara dan tidak mengimpor basis data.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from astria_common.errors import AstriaError
from astria_contracts.events.audit_record import AuditRecord
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Identity,
    Index,
    MetaData,
    Table,
    Text,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_audit.chain.canonical import canonical, normalize, sha256_hex
from astria_audit.chain.hashing import GENESIS_PREV, entry_hash, fmt_ts
from astria_audit.chain.verifier import JANGKAR_TIDAK_COCOK, SEQ_BERLUBANG, ChainVerifier

MAX_PAYLOAD_BYTES = 4096
LOCK_KEY = 0x4153_5452_4941  # "ASTRIA"
ANCHOR_LOCK_KEY = LOCK_KEY + 1
EXPORT_BATCH = 1000

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
Index("entries_actor_seq", entries.c.actor, entries.c.seq)
Index("entries_action_seq", entries.c.action, entries.c.seq)

anchors = Table(
    "anchors",
    metadata,
    Column("anchor_id", BigInteger, Identity(), primary_key=True),
    Column("seq", BigInteger, nullable=False),
    Column("entry_hash", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("exported_to", Text, nullable=True),
)
Index("anchors_seq", anchors.c.seq)

verify_jobs = Table(
    "verify_jobs",
    metadata,
    Column("job_id", Text, primary_key=True),
    Column("status", Text, nullable=False),
    Column("from_seq", BigInteger, nullable=False),
    Column("to_seq", BigInteger, nullable=True),
    Column("checked", BigInteger, nullable=False, server_default="0"),
    Column("ok", Boolean, nullable=True),
    Column("first_bad_seq", BigInteger, nullable=True),
    Column("reason", Text, nullable=True),
    Column("anchor_match", Boolean, nullable=True),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=True),
    Column("error", Text, nullable=True),
    CheckConstraint("status IN ('berjalan','selesai','gagal')", name="verify_jobs_status"),
)

# Append-only di tingkat basis data: UPDATE, DELETE, dan TRUNCATE pada entries dan anchors ditolak pemicu.
SETUP_SQL = [
    """
    CREATE OR REPLACE FUNCTION audit_tolak_ubah() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'audit.% hanya boleh ditambah (%)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
    END $$
    """,
    "DROP TRIGGER IF EXISTS entries_append_only ON entries",
    "CREATE TRIGGER entries_append_only BEFORE UPDATE OR DELETE ON entries"
    " FOR EACH ROW EXECUTE FUNCTION audit_tolak_ubah()",
    "DROP TRIGGER IF EXISTS entries_no_truncate ON entries",
    "CREATE TRIGGER entries_no_truncate BEFORE TRUNCATE ON entries"
    " FOR EACH STATEMENT EXECUTE FUNCTION audit_tolak_ubah()",
    "DROP TRIGGER IF EXISTS anchors_append_only ON anchors",
    "CREATE TRIGGER anchors_append_only BEFORE UPDATE OR DELETE ON anchors"
    " FOR EACH ROW EXECUTE FUNCTION audit_tolak_ubah()",
    "DROP TRIGGER IF EXISTS anchors_no_truncate ON anchors",
    "CREATE TRIGGER anchors_no_truncate BEFORE TRUNCATE ON anchors"
    " FOR EACH STATEMENT EXECUTE FUNCTION audit_tolak_ubah()",
    # Tabel entries dari Tahap 0 sudah ada, jadi create_all tidak membuat indeks baru di atasnya.
    "CREATE INDEX IF NOT EXISTS entries_actor_seq ON entries (actor, seq)",
    "CREATE INDEX IF NOT EXISTS entries_action_seq ON entries (action, seq)",
]


def request_fingerprint(record: AuditRecord) -> str:
    data = record.model_dump(mode="json")
    data["occurred_at"] = fmt_ts(record.occurred_at)
    return sha256_hex(canonical(data))


async def write(
    conn: AsyncConnection, record: AuditRecord, *, max_payload: int = MAX_PAYLOAD_BYTES
) -> tuple[dict[str, Any], bool]:
    """Tulis satu entri di transaksi `conn`. Mengembalikan (entri, duplikat)."""
    payload = normalize(record.payload)
    raw_payload = canonical(payload)
    if len(raw_payload) > max_payload:
        raise AstriaError("PAYLOAD_TERLALU_BESAR", f"payload melebihi {max_payload} byte", 413)
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
    entry = {str(k): row[k] for k in entries.c.keys() if k != "request_hash"}  # str: orjson menolak quoted_name
    entry["occurred_at"] = fmt_ts(row["occurred_at"])
    entry["recorded_at"] = fmt_ts(row["recorded_at"])
    return entry


async def head(conn: AsyncConnection) -> dict[str, Any] | None:
    row = (
        (await conn.execute(select(entries.c.seq, entries.c.entry_hash).order_by(entries.c.seq.desc()).limit(1)))
        .mappings()
        .first()
    )
    return dict(row) if row else None


async def query_entries(
    conn: AsyncConnection,
    *,
    from_seq: int = 0,
    limit: int = 100,
    actor: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
) -> tuple[list[dict[str, Any]], int | None]:
    """Satu halaman entri (filter cocok persis, digabung AND). Mengembalikan (entri, next_from_seq)."""
    stmt = select(entries).where(entries.c.seq >= from_seq)
    for column, value in (
        (entries.c.actor, actor),
        (entries.c.action, action),
        (entries.c.target_type, target_type),
        (entries.c.target_id, target_id),
    ):
        if value is not None:
            stmt = stmt.where(column == value)
    rows = (await conn.execute(stmt.order_by(entries.c.seq).limit(limit + 1))).mappings().all()
    items = [row_to_entry(r) for r in rows[:limit]]
    return items, (rows[limit]["seq"] if len(rows) > limit else None)


async def iter_entries(
    conn: AsyncConnection, *, from_seq: int = 1, to_seq: int | None = None, batch: int = EXPORT_BATCH
) -> AsyncIterator[dict[str, Any]]:
    """Entri berurutan dalam rentang, dibaca per kelompok dengan kursor `seq` (tidak memuat semuanya)."""
    cursor = from_seq
    while True:
        stmt = select(entries).where(entries.c.seq >= cursor)
        if to_seq is not None:
            stmt = stmt.where(entries.c.seq <= to_seq)
        rows = (await conn.execute(stmt.order_by(entries.c.seq).limit(batch))).mappings().all()
        if not rows:
            return
        for row in rows:
            yield row_to_entry(row)
        cursor = rows[-1]["seq"] + 1


def _result(
    verifier: ChainVerifier,
    *,
    from_seq: int,
    ok: bool,
    first_bad_seq: int | None = None,
    reason: str | None = None,
    anchor_match: bool | None = None,
) -> dict[str, Any]:
    return {
        "status": "selesai",
        "from_seq": from_seq,
        "to_seq": verifier.last_seq,
        "checked": verifier.checked,
        "ok": ok,
        "first_bad_seq": first_bad_seq,
        "reason": reason,
        "anchor_match": anchor_match,
    }


async def _anchor_mismatch(conn: AsyncConnection, from_seq: int, to_seq: int | None) -> tuple[bool | None, int | None]:
    """Bandingkan jangkar dalam rentang dengan entri aktual. (anchor_match, seq jangkar pertama yang tidak cocok)."""
    stmt = (
        select(anchors.c.seq, anchors.c.entry_hash, entries.c.entry_hash.label("actual"))
        .select_from(anchors.outerjoin(entries, entries.c.seq == anchors.c.seq))
        .where(anchors.c.seq >= from_seq)
        .order_by(anchors.c.seq)
    )
    if to_seq is not None:
        stmt = stmt.where(anchors.c.seq <= to_seq)
    rows = (await conn.execute(stmt)).mappings().all()
    if not rows:
        return None, None
    for row in rows:
        if row["actual"] != row["entry_hash"]:
            return False, row["seq"]
    return True, None


async def verify_range(
    conn: AsyncConnection, *, from_seq: int = 1, to_seq: int | None = None, batch: int = 1000
) -> dict[str, Any]:
    """Verifikasi streaming dalam kelompok. Berhenti di entri rusak pertama; tidak menulis apa pun.

    `from_seq` > 1 membaca entri `from_seq - 1` sebagai titik awal prev_hash. Setelah rantai, setiap jangkar dalam
    rentang dibandingkan dengan entri aktualnya (`anchor_match`; null bila tidak ada jangkar dalam rentang).
    """
    prev = GENESIS_PREV
    if from_seq > 1:
        before = (
            await conn.execute(select(entries.c.entry_hash).where(entries.c.seq == from_seq - 1))
        ).scalar_one_or_none()
        if before is None:
            verifier = ChainVerifier(expected_seq=from_seq)
            return _result(verifier, from_seq=from_seq, ok=False, first_bad_seq=from_seq, reason=SEQ_BERLUBANG)
        prev = before
    verifier = ChainVerifier(prev_hash=prev, expected_seq=from_seq)

    cursor = from_seq
    while True:
        stmt = select(entries).where(entries.c.seq >= cursor)
        if to_seq is not None:
            stmt = stmt.where(entries.c.seq <= to_seq)
        rows = (await conn.execute(stmt.order_by(entries.c.seq).limit(batch))).mappings().all()
        if not rows:
            break
        for row in rows:
            entry = row_to_entry(row)
            reason = verifier.check(entry)
            if reason is not None:
                match, _ = await _anchor_mismatch(conn, from_seq, to_seq)
                return _result(
                    verifier,
                    from_seq=from_seq,
                    ok=False,
                    first_bad_seq=entry["seq"],
                    reason=reason,
                    anchor_match=match,
                )
        cursor = rows[-1]["seq"] + 1

    match, bad_anchor_seq = await _anchor_mismatch(conn, from_seq, to_seq)
    if match is False:
        return _result(
            verifier,
            from_seq=from_seq,
            ok=False,
            first_bad_seq=bad_anchor_seq,
            reason=JANGKAR_TIDAK_COCOK,
            anchor_match=False,
        )
    return _result(verifier, from_seq=from_seq, ok=True, anchor_match=match)


async def verify(conn: AsyncConnection, *, batch: int = 1000) -> dict[str, Any]:
    """Verifikasi seluruh rantai (API Tahap 0)."""
    return await verify_range(conn, batch=batch)


# --- jangkar ---


def anchor_to_dict(row: Any) -> dict[str, Any]:
    return {
        "anchor_id": row["anchor_id"],
        "seq": row["seq"],
        "entry_hash": row["entry_hash"],
        "created_at": fmt_ts(row["created_at"]),
        "exported_to": row["exported_to"],
    }


async def create_anchor(conn: AsyncConnection) -> tuple[dict[str, Any], bool] | None:
    """Jangkar kepala rantai saat ini. Mengembalikan (jangkar, baru) atau None bila rantai kosong.

    Bila kepala sama dengan jangkar terakhir, jangkar itu dikembalikan tanpa menulis ganda (baru=False).
    """
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ANCHOR_LOCK_KEY})
    current = await head(conn)
    if current is None:
        return None
    last = (await conn.execute(select(anchors).order_by(anchors.c.anchor_id.desc()).limit(1))).mappings().first()
    if last is not None and last["seq"] == current["seq"] and last["entry_hash"] == current["entry_hash"]:
        return anchor_to_dict(last), False
    row = (
        (
            await conn.execute(
                insert(anchors).values(seq=current["seq"], entry_hash=current["entry_hash"]).returning(*anchors.c)
            )
        )
        .mappings()
        .one()
    )
    return anchor_to_dict(row), True


async def latest_anchor(conn: AsyncConnection) -> dict[str, Any] | None:
    row = (await conn.execute(select(anchors).order_by(anchors.c.anchor_id.desc()).limit(1))).mappings().first()
    return anchor_to_dict(row) if row else None


async def list_anchors(conn: AsyncConnection, limit: int = 50) -> list[dict[str, Any]]:
    rows = (await conn.execute(select(anchors).order_by(anchors.c.anchor_id.desc()).limit(limit))).mappings().all()
    return [anchor_to_dict(r) for r in rows]


# --- tugas verifikasi ---


async def insert_job(conn: AsyncConnection, job_id: str, from_seq: int) -> None:
    await conn.execute(
        insert(verify_jobs).values(
            job_id=job_id, status="berjalan", from_seq=from_seq, checked=0, started_at=datetime.now(UTC)
        )
    )


async def finish_job(conn: AsyncConnection, job_id: str, result: dict[str, Any]) -> None:
    await conn.execute(
        update(verify_jobs)
        .where(verify_jobs.c.job_id == job_id)
        .values(
            status="selesai",
            to_seq=result["to_seq"],
            checked=result["checked"],
            ok=result["ok"],
            first_bad_seq=result["first_bad_seq"],
            reason=result["reason"],
            anchor_match=result["anchor_match"],
            finished_at=datetime.now(UTC),
        )
    )


async def fail_job(conn: AsyncConnection, job_id: str, error: str) -> None:
    await conn.execute(
        update(verify_jobs)
        .where(verify_jobs.c.job_id == job_id, verify_jobs.c.status == "berjalan")
        .values(status="gagal", reason="tugas_gagal", error=error, finished_at=datetime.now(UTC))
    )


async def fail_stale_jobs(conn: AsyncConnection, before: datetime) -> int:
    """Tandai tugas `berjalan` yang dimulai sebelum `before` (sisa proses sebelumnya) sebagai gagal."""
    result = await conn.execute(
        update(verify_jobs)
        .where(verify_jobs.c.status == "berjalan", verify_jobs.c.started_at < before)
        .values(
            status="gagal",
            reason="tugas_gagal",
            error="layanan dimulai ulang saat tugas berjalan",
            finished_at=datetime.now(UTC),
        )
    )
    return result.rowcount


async def get_job(conn: AsyncConnection, job_id: str) -> dict[str, Any] | None:
    row = (await conn.execute(select(verify_jobs).where(verify_jobs.c.job_id == job_id))).mappings().first()
    if row is None:
        return None
    return {
        "job_id": row["job_id"],
        "status": row["status"],
        "from_seq": row["from_seq"],
        "to_seq": row["to_seq"],
        "checked": row["checked"],
        "ok": row["ok"],
        "first_bad_seq": row["first_bad_seq"],
        "reason": row["reason"],
        "anchor_match": row["anchor_match"],
        "started_at": fmt_ts(row["started_at"]),
        "finished_at": fmt_ts(row["finished_at"]) if row["finished_at"] else None,
    }
