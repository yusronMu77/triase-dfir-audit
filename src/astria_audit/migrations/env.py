"""Lingkungan Alembic audit. Hanya mode online (PostgreSQL); tidak ada mode offline.

Dipanggil dari `astria_audit.skema.terapkan`, yang memberi koneksi lewat `config.attributes["connection"]`.
Dijalankan langsung (mis. `alembic current` dengan `alembic.ini` lokal), koneksi diambil dari
`ASTRIA_DATABASE_URL` dan skema dari `ASTRIA_DB_SCHEMA`.
"""

import os

from alembic import context
from astria_common.db import normalize_url
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import Connection

from astria_audit.skema import connect_args

config = context.config


def _jalankan(connection: Connection, schema: str | None) -> None:
    context.configure(connection=connection, version_table_schema=schema, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _jalankan(connection, config.attributes.get("schema"))
        return
    url = config.attributes.get("url") or os.environ.get("ASTRIA_DATABASE_URL")
    if not url:
        raise RuntimeError("ASTRIA_DATABASE_URL belum diisi")
    schema = config.attributes.get("schema") or os.environ.get("ASTRIA_DB_SCHEMA") or None
    engine = create_engine(normalize_url(url), poolclass=pool.NullPool, connect_args=connect_args(schema))
    try:
        with engine.connect() as connection:
            _jalankan(connection, schema)
            connection.commit()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("mode offline tidak didukung; jalankan migrasi online")
run_migrations_online()
