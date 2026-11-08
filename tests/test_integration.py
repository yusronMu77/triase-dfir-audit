"""Uji rantai audit dengan PostgreSQL sungguhan (butuh ASTRIA_TEST_DATABASE_URL)."""

import os
import uuid
from datetime import UTC, datetime

import pytest
from astria_common.db import Database
from astria_common.errors import AstriaError
from astria_contracts.events.audit_record import AuditRecord
from pydantic import SecretStr
from sqlalchemy import text

from astria_audit import chain

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
    database = Database(SecretStr(DB_URL or ""), schema=schema, metadata=[chain.metadata], setup_sql=chain.SETUP_SQL)
    await database.start()
    await database.wait_ready(10)
    yield database
    async with database.engine.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    await database.stop()


async def test_chain_write_duplicate_and_verify(db) -> None:
    first = record("k1", n=1)
    async with db.engine.begin() as conn:
        e1, dup1 = await chain.write(conn, first)
        e2, _ = await chain.write(conn, record("k2", n=2))
        again, dup2 = await chain.write(conn, first)
    assert (e1["seq"], e2["seq"]) == (1, 2)
    assert e1["prev_hash"] == chain.GENESIS_PREV
    assert e2["prev_hash"] == e1["entry_hash"]
    assert not dup1 and dup2
    assert again["seq"] == 1

    with pytest.raises(AstriaError) as err:
        async with db.engine.begin() as conn:
            await chain.write(conn, record("k1", n=999))
    assert err.value.status == 409

    async with db.engine.connect() as conn:
        result = await chain.verify(conn)
    assert result["ok"] and result["checked"] == 2


async def test_entries_are_append_only(db) -> None:
    async with db.engine.begin() as conn:
        await chain.write(conn, record("k1"))
    for statement in ("UPDATE entries SET actor = 'x'", "DELETE FROM entries", "TRUNCATE entries"):
        with pytest.raises(Exception, match="hanya boleh ditambah"):
            async with db.engine.begin() as conn:
                await conn.execute(text(statement))


async def test_verify_detects_tampering(db) -> None:
    async with db.engine.begin() as conn:
        await chain.write(conn, record("k1"))
        await chain.write(conn, record("k2"))
    async with db.engine.begin() as conn:
        await conn.execute(text("ALTER TABLE entries DISABLE TRIGGER entries_append_only"))
        await conn.execute(text("UPDATE entries SET actor = 'svc:palsu' WHERE seq = 1"))
        await conn.execute(text("ALTER TABLE entries ENABLE TRIGGER entries_append_only"))
    async with db.engine.connect() as conn:
        result = await chain.verify(conn)
    assert not result["ok"]
    assert result["first_bad_seq"] == 1
    assert result["reason"] == "entry_hash_tidak_cocok"
