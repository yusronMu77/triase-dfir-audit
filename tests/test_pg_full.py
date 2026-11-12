"""Uji versi penuh terhadap PostgreSQL sungguhan (butuh ASTRIA_TEST_DATABASE_URL): verifikasi, jangkar, tugas."""

import asyncio
import os
import uuid
from datetime import UTC, datetime

import pytest
from astria_common.db import Database
from astria_common.errors import AstriaError
from astria_contracts.events.audit_record import AuditRecord
from pydantic import SecretStr
from sqlalchemy import text

from astria_audit import chain, workers
from astria_audit.chain import store
from astria_audit.skema import terapkan

DB_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not DB_URL, reason="ASTRIA_TEST_DATABASE_URL tidak diisi"),
]


def record(key: str, **payload: object) -> AuditRecord:
    return AuditRecord(
        idempotency_key=key,
        occurred_at=datetime.now(UTC),
        actor="svc:ingest",
        actor_type="service",
        action="ingest.sample.emitted",
        target_type="job",
        target_id="ING-1",
        via="system",
        payload=payload,
    )


@pytest.fixture
async def db():
    schema = f"t_{uuid.uuid4().hex[:8]}"
    terapkan(DB_URL or "", schema)  # skema lewat migrasi, sama seperti layanan
    database = Database(SecretStr(DB_URL or ""), schema=schema)
    await database.start()
    await database.wait_ready(10)
    yield database
    async with database.engine.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    await database.stop()


async def fill(db: Database, count: int, prefix: str = "k") -> None:
    async with db.engine.begin() as conn:
        for i in range(1, count + 1):
            await chain.write(conn, record(f"{prefix}{i}", n=i))


async def tamper(db: Database, statement: str, **params: object) -> None:
    async with db.engine.begin() as conn:
        await conn.execute(text("ALTER TABLE entries DISABLE TRIGGER entries_append_only"))
        await conn.execute(text(statement), params)
        await conn.execute(text("ALTER TABLE entries ENABLE TRIGGER entries_append_only"))


async def test_verify_detects_tamper_at_batch_boundaries(db: Database) -> None:
    await fill(db, 7)
    # batch=2: kelompok [1,2] [3,4] [5,6] [7]. seq 2 = ujung kelompok, 3 = awal kelompok, 7 = kelompok terakhir.
    for seq in (2, 3, 7):
        await tamper(db, "UPDATE entries SET payload = jsonb_build_object('n', 999) WHERE seq = :s", s=seq)
        async with db.engine.connect() as conn:
            result = await store.verify_range(conn, batch=2)
        assert (result["ok"], result["first_bad_seq"], result["reason"]) == (False, seq, "payload_hash_tidak_cocok")
        assert result["checked"] == seq - 1
        await tamper(db, "UPDATE entries SET payload = jsonb_build_object('n', CAST(:s AS int)) WHERE seq = :s", s=seq)
    async with db.engine.connect() as conn:
        assert (await store.verify_range(conn, batch=2))["ok"]


async def test_verify_detects_deleted_entry_in_the_middle(db: Database) -> None:
    await fill(db, 6)
    await tamper(db, "DELETE FROM entries WHERE seq = 4")
    async with db.engine.connect() as conn:
        result = await store.verify_range(conn, batch=2)
    assert (result["ok"], result["first_bad_seq"], result["reason"]) == (False, 5, "nomor_urut_berlubang")


async def test_partial_verify_from_seq(db: Database) -> None:
    await fill(db, 6)
    async with db.engine.connect() as conn:
        part = await store.verify_range(conn, from_seq=3, to_seq=5, batch=2)
        beyond = await store.verify_range(conn, from_seq=50)
    assert (part["ok"], part["checked"], part["from_seq"], part["to_seq"]) == (True, 3, 3, 5)
    assert beyond["ok"] is False and beyond["reason"] == "nomor_urut_berlubang"
    await tamper(db, "UPDATE entries SET actor = 'svc:palsu' WHERE seq = 2")
    async with db.engine.connect() as conn:
        # entri 2 rusak, tetapi verifikasi dari seq 3 hanya memakai entry_hash tersimpan entri 2 sebagai prev
        assert (await store.verify_range(conn, from_seq=3))["ok"] is True
        full = await store.verify_range(conn)
    assert full["first_bad_seq"] == 2


async def test_two_concurrent_writers_leave_no_gap(db: Database) -> None:
    async def writer(tag: str) -> None:
        for i in range(15):
            async with db.engine.begin() as conn:
                await chain.write(conn, record(f"{tag}-{i}", n=i))

    await asyncio.gather(writer("a"), writer("b"))
    async with db.engine.connect() as conn:
        seqs = [r[0] for r in (await conn.execute(text("SELECT seq FROM entries ORDER BY seq"))).all()]
        result = await store.verify_range(conn, batch=7)
    assert seqs == list(range(1, 31))
    assert result["ok"] and result["checked"] == 30


async def test_anchor_match_true_false_and_none(db: Database) -> None:
    await fill(db, 4)
    async with db.engine.connect() as conn:
        assert (await store.verify_range(conn))["anchor_match"] is None
    async with db.engine.begin() as conn:
        created = await store.create_anchor(conn)
        again = await store.create_anchor(conn)
    assert created is not None and again is not None
    anchor, is_new = created
    same, is_new_again = again
    assert is_new and not is_new_again and same["anchor_id"] == anchor["anchor_id"] and anchor["seq"] == 4
    async with db.engine.connect() as conn:
        ok = await store.verify_range(conn)
    assert ok["ok"] and ok["anchor_match"] is True

    fake = "f" * 64
    async with db.engine.begin() as conn:  # jangkar palsu pada seq 2: rantai utuh, jangkar tidak cocok
        await conn.execute(text("INSERT INTO anchors (seq, entry_hash) VALUES (2, :h)"), {"h": fake})
    async with db.engine.connect() as conn:
        bad = await store.verify_range(conn)
        outside = await store.verify_range(conn, from_seq=3)  # jangkar palsu di luar rentang
    assert (bad["ok"], bad["anchor_match"], bad["reason"], bad["first_bad_seq"]) == (
        False,
        False,
        "jangkar_tidak_cocok",
        2,
    )
    assert outside["ok"] and outside["anchor_match"] is True


async def test_anchor_detects_deleted_tail(db: Database) -> None:
    await fill(db, 5)
    async with db.engine.begin() as conn:
        await store.create_anchor(conn)  # jangkar di seq 5
    await tamper(db, "DELETE FROM entries WHERE seq = 5")  # ekor dihapus: rantai sisa tetap konsisten
    async with db.engine.connect() as conn:
        result = await store.verify_range(conn)
    assert (result["ok"], result["anchor_match"], result["first_bad_seq"]) == (False, False, 5)


async def test_create_anchor_on_empty_chain_is_none(db: Database) -> None:
    async with db.engine.begin() as conn:
        assert await store.create_anchor(conn) is None
    async with db.engine.connect() as conn:
        assert await store.latest_anchor(conn) is None


async def test_anchors_are_append_only(db: Database) -> None:
    await fill(db, 2)
    async with db.engine.begin() as conn:
        await store.create_anchor(conn)
    for statement in ("UPDATE anchors SET exported_to = 'x'", "DELETE FROM anchors", "TRUNCATE anchors"):
        with pytest.raises(Exception, match="hanya boleh ditambah"):
            async with db.engine.begin() as conn:
                await conn.execute(text(statement))


async def test_anchor_scheduler_tick_does_not_duplicate(db: Database) -> None:
    scheduler = workers.AnchorScheduler(db, interval_min=0)
    assert await scheduler.tick() is None  # rantai kosong
    await fill(db, 3)
    first = await scheduler.tick()
    assert first is not None and first["seq"] == 3
    assert await scheduler.tick() is None  # kepala belum berubah
    await fill(db, 1, prefix="lagi")
    second = await scheduler.tick()
    assert second is not None and second["seq"] == 4
    async with db.engine.connect() as conn:
        assert [a["seq"] for a in await store.list_anchors(conn)] == [4, 3]


async def test_stale_running_jobs_are_marked_failed_on_start(db: Database) -> None:
    async with db.engine.begin() as conn:
        await store.insert_job(conn, "ver_lama1", 1)
    runner = workers.VerifyRunner(db)
    await runner.start()
    assert runner._boot is not None
    await runner._boot
    async with db.engine.connect() as conn:
        job = await store.get_job(conn, "ver_lama1")
    assert job is not None
    assert job["status"] == "gagal" and job["reason"] == "tugas_gagal" and job["finished_at"] is not None
    # tugas baru sesudah start tidak ikut ditandai
    job_id, task = await runner.submit(1, None)
    await task
    async with db.engine.connect() as conn:
        done = await store.get_job(conn, job_id)
    assert done is not None and done["status"] == "selesai" and done["ok"] is True
    await runner.stop()


async def test_iter_entries_batches_and_range(db: Database) -> None:
    await fill(db, 7)
    async with db.engine.connect() as conn:
        got = [e["seq"] async for e in store.iter_entries(conn, from_seq=2, to_seq=6, batch=2)]
    assert got == [2, 3, 4, 5, 6]


async def test_query_entries_filters_and_pages(db: Database) -> None:
    rows = [("usr_a", "x.one"), ("usr_b", "x.one"), ("usr_a", "x.two"), ("usr_a", "x.one")]
    async with db.engine.begin() as conn:
        for i, (actor, action) in enumerate(rows):
            rec = record(f"q{i}").model_copy(update={"actor": actor, "action": action, "target_id": f"T{i % 2}"})
            await chain.write(conn, rec)
    async with db.engine.connect() as conn:
        items, nxt = await store.query_entries(conn, actor="usr_a", action="x.one", limit=10)
        page, page_next = await store.query_entries(conn, actor="usr_a", limit=2)
        by_target, _ = await store.query_entries(conn, target_id="T1")
    assert [e["seq"] for e in items] == [1, 4] and nxt is None
    assert [e["seq"] for e in page] == [1, 3] and page_next == 4
    assert [e["seq"] for e in by_target] == [2, 4]


async def test_actor_and_action_indexes_exist(db: Database) -> None:
    query = text("SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
    async with db.engine.connect() as conn:
        names = {r[0] for r in (await conn.execute(query)).all()}
    assert {"entries_actor_seq", "entries_action_seq", "anchors_seq"} <= names


async def test_oversized_payload_uses_configured_limit(db: Database) -> None:
    async with db.engine.begin() as conn:
        with pytest.raises(AstriaError) as err:
            await chain.write(conn, record("big", blob="x" * 300), max_payload=100)
    assert err.value.status == 413


async def test_export_cli_roundtrip_verifies_offline(db: Database, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from astria_audit.__main__ import main

    await fill(db, 5)
    schema = db._schema
    monkeypatch.setenv("ASTRIA_ENV", "test")
    monkeypatch.setenv("ASTRIA_DATABASE_URL", DB_URL or "")
    monkeypatch.setenv("ASTRIA_DB_SCHEMA", schema or "")
    out = tmp_path / "ekspor.jsonl"

    def run_cli(argv: list[str]) -> int:
        return main(argv)

    assert await asyncio.to_thread(run_cli, ["export", "--out", str(out)]) == 0
    assert out.read_bytes().count(b"\n") == 5
    assert main(["verify-file", str(out)]) == 0
    part = tmp_path / "bagian.jsonl"
    assert await asyncio.to_thread(run_cli, ["export", "--from", "2", "--to", "4", "--out", str(part)]) == 0
    assert part.read_bytes().count(b"\n") == 3
    assert main(["verify-file", str(part)]) == 0
