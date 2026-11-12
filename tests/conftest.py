import os

import pytest


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _clean_astria_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Uji tidak boleh membaca ASTRIA_* milik kontainer dev."""
    for key in list(os.environ):
        if key.startswith("ASTRIA_") and not key.startswith("ASTRIA_TEST_"):
            monkeypatch.delenv(key, raising=False)


PG_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")


@pytest.fixture
def pg_schema():
    """Nama skema sementara di PostgreSQL uji; dibuang setelah uji. Di-skip bila ASTRIA_TEST_DATABASE_URL kosong."""
    if not PG_URL:
        pytest.skip("ASTRIA_TEST_DATABASE_URL tidak diisi")
    import asyncio
    import uuid

    from astria_common.db import normalize_url
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    schema = f"t_{uuid.uuid4().hex[:8]}"
    yield schema

    async def drop() -> None:
        engine = create_async_engine(normalize_url(PG_URL))
        async with engine.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await engine.dispose()

    asyncio.run(drop())
