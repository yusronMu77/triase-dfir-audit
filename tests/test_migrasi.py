"""Migrasi skema audit (Alembic) terhadap PostgreSQL sungguhan (butuh ASTRIA_TEST_DATABASE_URL, bila kosong di-skip).

Keadaan "lama" (Tahap 0 dan 0.2.0) dibentuk di sini dengan `create_all` dan pemicu yang sama dengan kode lama.
"""

import json
from collections.abc import Iterator
from typing import Any

import pytest
from conftest import PG_URL
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from astria_audit import __main__ as cli
from astria_audit.chain import store
from astria_audit.main import build_app
from astria_audit.settings import Settings
from astria_audit.skema import BASELINE_TRIGGERS, SkemaGagal, connect_args, terapkan

# Pemicu dari kode Tahap 0 / 0.2.0 (SETUP_SQL lama), disalin apa adanya sebagai keadaan "sebelum migrasi".
LEGACY_PEMICU = [
    """
    CREATE OR REPLACE FUNCTION audit_tolak_ubah() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'audit.% hanya boleh ditambah (%)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
    END $$
    """,
    "CREATE TRIGGER entries_append_only BEFORE UPDATE OR DELETE ON entries"
    " FOR EACH ROW EXECUTE FUNCTION audit_tolak_ubah()",
    "CREATE TRIGGER entries_no_truncate BEFORE TRUNCATE ON entries"
    " FOR EACH STATEMENT EXECUTE FUNCTION audit_tolak_ubah()",
    "CREATE TRIGGER anchors_append_only BEFORE UPDATE OR DELETE ON anchors"
    " FOR EACH ROW EXECUTE FUNCTION audit_tolak_ubah()",
    "CREATE TRIGGER anchors_no_truncate BEFORE TRUNCATE ON anchors"
    " FOR EACH STATEMENT EXECUTE FUNCTION audit_tolak_ubah()",
]

INSERT_ENTRY = text(
    "INSERT INTO entries (seq, occurred_at, recorded_at, actor, actor_type, action, target_type, target_id, via,"
    " idempotency_key, request_hash, payload, payload_hash, prev_hash, entry_hash)"
    " VALUES (1, now(), now(), 'svc:uji', 'service', 'uji.dibuat', 'uji', 'U-1', 'system', 'k-uji', 'rh',"
    " CAST(:payload AS jsonb), 'ph', :prev, 'eh')"
)
ENTRY_PARAMS = {"payload": json.dumps({"n": 1}), "prev": "0" * 64}


def _engine(schema: str | None) -> Engine:
    return create_engine(PG_URL or "", connect_args=connect_args(schema))


def _query(schema: str, sql: str, **params: Any) -> list[tuple]:
    engine = _engine(schema)
    try:
        with engine.connect() as conn:
            return [tuple(r) for r in conn.execute(text(sql), {"s": schema, **params}).all()]
    finally:
        engine.dispose()


def _katalog(schema: str) -> dict[str, list[tuple]]:
    """Bentuk skema yang dibandingkan: kolom, indeks, dan batasan (nama skema diganti 'S')."""
    return {
        "kolom": _query(
            schema,
            "SELECT table_name, column_name, data_type, is_nullable, column_default, is_identity,"
            " identity_generation FROM information_schema.columns WHERE table_schema = :s ORDER BY 1, 2",
        ),
        "indeks": _query(
            schema,
            "SELECT tablename, indexname, replace(indexdef, :s, 'S') FROM pg_indexes"
            " WHERE schemaname = :s ORDER BY 1, 2",
        ),
        "batasan": _query(
            schema,
            "SELECT c.relname, k.conname, k.contype, pg_get_constraintdef(k.oid) FROM pg_constraint k"
            " JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = :s ORDER BY 1, 2",
        ),
    }


def _pemicu(schema: str) -> set[str]:
    return {
        r[0]
        for r in _query(
            schema,
            "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
            " JOIN pg_namespace n ON n.oid = c.relnamespace WHERE NOT t.tgisinternal AND n.nspname = :s",
        )
    }


def _versi(schema: str) -> str | None:
    engine = _engine(schema)
    try:
        with engine.connect() as conn:
            if "alembic_version" not in inspect(conn).get_table_names(schema=schema):
                return None
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    finally:
        engine.dispose()


def _oid_entries(schema: str) -> int:
    return _query(
        schema,
        "SELECT c.oid::bigint FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = :s AND c.relname = 'entries'",
    )[0][0]


def _buat_lama(schema: str, *, pemicu: bool = True, isi: bool = False) -> None:
    """Keadaan Tahap 0 / 0.2.0: tabel dari create_all (tanpa riwayat Alembic), opsional pemicu dan satu entri."""
    engine = _engine(None)
    try:
        with engine.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
        engine.dispose()
        engine = _engine(schema)
        with engine.begin() as conn:
            store.metadata.create_all(conn)
            if pemicu:
                for statement in LEGACY_PEMICU:
                    conn.execute(text(statement))
            if isi:
                conn.execute(INSERT_ENTRY, ENTRY_PARAMS)
    finally:
        engine.dispose()


@pytest.fixture
def ref_schema(pg_schema: str) -> Iterator[str]:
    """Skema pembanding yang dibentuk langsung dari metadata (tanpa Alembic)."""
    name = pg_schema + "_r"
    yield name
    engine = _engine(None)
    with engine.begin() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{name}" CASCADE'))
    engine.dispose()


def test_kosong_menjadi_skema_setara_dengan_metadata(pg_schema: str, ref_schema: str) -> None:
    _buat_lama(ref_schema, pemicu=False)  # hanya bentuk tabel; pemicu diperiksa terpisah
    assert terapkan(PG_URL or "", pg_schema) == "dibuat"
    # alembic_version hanya ada di hasil migrasi; sisanya harus identik.
    tanpa_riwayat = {k: [r for r in v if r[0] != "alembic_version"] for k, v in _katalog(pg_schema).items()}
    assert tanpa_riwayat == _katalog(ref_schema)
    assert _versi(pg_schema) == "0001_baseline"
    assert _pemicu(pg_schema) >= set(BASELINE_TRIGGERS)


def test_idempoten(pg_schema: str) -> None:
    assert terapkan(PG_URL or "", pg_schema) == "dibuat"
    assert terapkan(PG_URL or "", pg_schema) == "sudah_terbaru"
    assert _versi(pg_schema) == "0001_baseline"


def test_stamp_tanpa_ddl_dan_data_utuh(pg_schema: str) -> None:
    _buat_lama(pg_schema, isi=True)
    oid_sebelum = _oid_entries(pg_schema)
    assert _versi(pg_schema) is None

    assert terapkan(PG_URL or "", pg_schema) == "ditandai"

    assert _versi(pg_schema) == "0001_baseline"
    assert _oid_entries(pg_schema) == oid_sebelum  # tabel tidak dibuat ulang
    assert _query(pg_schema, "SELECT count(*) FROM entries")[0][0] == 1
    assert _pemicu(pg_schema) >= set(BASELINE_TRIGGERS)


def test_stamp_menolak_skema_tanpa_pemicu(pg_schema: str) -> None:
    _buat_lama(pg_schema, pemicu=False)
    with pytest.raises(SkemaGagal, match="belum lengkap"):
        terapkan(PG_URL or "", pg_schema)
    assert _versi(pg_schema) is None  # tidak ada riwayat yang ditulis


def test_pemicu_append_only_tetap_aktif_sesudah_migrasi(pg_schema: str) -> None:
    terapkan(PG_URL or "", pg_schema)
    engine = _engine(pg_schema)
    try:
        with engine.begin() as conn:
            conn.execute(INSERT_ENTRY, ENTRY_PARAMS)
            conn.execute(text("INSERT INTO anchors (seq, entry_hash) VALUES (1, 'eh')"))
        for perintah in (
            "UPDATE entries SET actor = 'x'",
            "DELETE FROM entries",
            "TRUNCATE entries",
            "UPDATE anchors SET seq = 2",
            "DELETE FROM anchors",
            "TRUNCATE anchors",
        ):
            with pytest.raises(DBAPIError, match="hanya boleh ditambah"), engine.begin() as conn:
                conn.execute(text(perintah))
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM entries")).scalar_one() == 1
    finally:
        engine.dispose()


def test_sqlite_ditolak() -> None:
    with pytest.raises(SkemaGagal, match="PostgreSQL"):
        terapkan("sqlite+aiosqlite:///./tidak-dipakai.db")


def test_cli_migrate(pg_schema: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("ASTRIA_ENV", "test")
    monkeypatch.setenv("ASTRIA_DATABASE_URL", PG_URL or "")
    monkeypatch.setenv("ASTRIA_DB_SCHEMA", pg_schema)
    assert cli.main(["migrate"]) == 0
    assert cli.main(["migrate"]) == 0
    assert capsys.readouterr().out.splitlines() == ["migrasi audit: dibuat", "migrasi audit: sudah_terbaru"]


def test_start_pada_basis_data_lama_menandai_skema(pg_schema: str) -> None:
    _buat_lama(pg_schema, isi=True)
    settings = Settings(env="test", database_url=SecretStr(PG_URL or ""), db_schema=pg_schema, anchor_interval_min=0)
    with TestClient(build_app(settings)) as client:
        ready = client.get("/ready")
        assert ready.status_code == 200
        assert ready.json()["checks"]["migrasi"] == {"status": "ok", "detail": "ditandai"}
    assert _versi(pg_schema) == "0001_baseline"
