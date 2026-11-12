"""Penerapan skema audit lewat Alembic (PostgreSQL). Dipakai `astria-audit migrate` dan start layanan.

Keadaan awal menentukan tindakan, dan semuanya berjalan di bawah kunci advisory bersama sehingga replika yang start
bersamaan tidak balapan:

- belum ada tabel audit: `upgrade head` membuat skema baseline (`dibuat`);
- tabel audit sudah ada tanpa riwayat Alembic (basis data dari `create_all` Tahap 0 atau 0.2.0): `stamp head` setelah
  memastikan semua tabel dan pemicu append-only ada, tanpa DDL apa pun (`ditandai`);
- ada riwayat: `upgrade head`, atau tidak melakukan apa-apa bila sudah di head (`diperbarui` / `sudah_terbaru`).

Tabel yang hanya sebagian ada ditolak (`SkemaGagal`); tidak ada tebakan diam-diam pada buku besar.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from astria_common.db import dialect_of, normalize_url
from sqlalchemy import create_engine, inspect, pool, text
from sqlalchemy.engine import Connection

from astria_audit.chain.store import LOCK_KEY

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
MIGRASI_LOCK_KEY = LOCK_KEY + 2  # LOCK_KEY (+1 = jangkar); +2 = migrasi
BASELINE_TABLES = ("entries", "anchors", "verify_jobs")
BASELINE_TRIGGERS = ("entries_append_only", "entries_no_truncate", "anchors_append_only", "anchors_no_truncate")
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")

Tindakan = Literal["dibuat", "ditandai", "diperbarui", "sudah_terbaru"]


class SkemaGagal(RuntimeError):
    """Migrasi tidak bisa diterapkan dengan aman; pesan ditujukan ke operator."""


def connect_args(schema: str | None) -> dict[str, str]:
    return {"options": f"-csearch_path={schema}"} if schema else {}


def konfigurasi(url: str, schema: str | None) -> Config:
    """Konfigurasi Alembic tanpa berkas ini (`alembic.ini`): lokasi skrip dan koneksi diberikan lewat atribut."""
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["url"] = url
    cfg.attributes["schema"] = schema
    return cfg


def terapkan(url: str, schema: str | None = None) -> Tindakan:
    """Terapkan migrasi ke basis data `url` (skema `schema` bila diisi). Mengembalikan tindakan yang diambil."""
    if dialect_of(url) != "postgresql":
        raise SkemaGagal("skema audit hanya untuk PostgreSQL (JSONB dan identity column)")
    if schema is not None and not _IDENT.match(schema):
        raise SkemaGagal(f"nama skema tidak valid: {schema!r}")
    engine = create_engine(normalize_url(url), poolclass=pool.NullPool, connect_args=connect_args(schema))
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRASI_LOCK_KEY})
            try:
                tindakan = _terapkan_terkunci(conn, url, schema)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": MIGRASI_LOCK_KEY})
                conn.commit()
    finally:
        engine.dispose()
    return tindakan


def _terapkan_terkunci(conn: Connection, url: str, schema: str | None) -> Tindakan:
    if schema is not None and schema not in inspect(conn).get_schema_names():
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    tabel = set(inspect(conn).get_table_names(schema=schema))
    cfg = konfigurasi(url, schema)
    cfg.attributes["connection"] = conn
    head = ScriptDirectory.from_config(cfg).get_current_head()

    if "alembic_version" in tabel:
        current = MigrationContext.configure(conn, opts={"version_table_schema": schema}).get_current_revision()
        if current == head:
            return "sudah_terbaru"
        command.upgrade(cfg, "head")
        return "diperbarui"

    if "entries" in tabel:
        kurang = [t for t in BASELINE_TABLES if t not in tabel]
        kurang += [f"pemicu {p}" for p in _pemicu_hilang(conn, schema)]
        if kurang:
            raise SkemaGagal(
                "skema audit sudah ada tetapi belum lengkap (hilang: " + ", ".join(kurang) + "); "
                "lengkapi atau bersihkan secara manual, lalu jalankan ulang"
            )
        command.stamp(cfg, "head")
        return "ditandai"

    if tabel & set(BASELINE_TABLES):
        raise SkemaGagal("sebagian tabel audit ada tanpa tabel entries; periksa basis data secara manual")
    command.upgrade(cfg, "head")
    return "dibuat"


def _pemicu_hilang(conn: Connection, schema: str | None) -> list[str]:
    sql = text(
        "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE NOT t.tgisinternal AND n.nspname = COALESCE(:schema, current_schema())"
    )
    ada = {row[0] for row in conn.execute(sql, {"schema": schema})}
    return [p for p in BASELINE_TRIGGERS if p not in ada]
