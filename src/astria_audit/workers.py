"""Penulisan bermetrik, pelari tugas verifikasi, dan penjadwal jangkar (komponen latar)."""

from __future__ import annotations

import asyncio
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from astria_common.component import Check
from astria_common.db import Database
from astria_common.errors import AstriaError
from astria_common.log import get_logger
from astria_contracts.events.audit_record import AuditRecord
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_audit import metrics
from astria_audit.chain import store

log = get_logger(__name__)


async def append(
    conn: AsyncConnection, record: AuditRecord, *, via: str, max_payload: int = store.MAX_PAYLOAD_BYTES
) -> tuple[dict[str, Any], bool]:
    """`store.write` dengan metrik. `via` = jalur masuk (`sync` atau `event`)."""
    started = time.perf_counter()
    try:
        entry, duplicate = await store.write(conn, record, max_payload=max_payload)
    except AstriaError:
        metrics.RECORDS.labels(via, "ditolak").inc()
        raise
    metrics.WRITE_DURATION.observe(time.perf_counter() - started)
    metrics.RECORDS.labels(via, "duplikat" if duplicate else "ok").inc()
    if not duplicate:
        metrics.CHAIN_LENGTH.set(entry["seq"])
    return entry, duplicate


class VerifyRunner:
    """Menjalankan tugas verifikasi di latar. Saat start, tugas `berjalan` sisa proses sebelumnya ditandai gagal
    dan gauge panjang rantai diisi dari kepala rantai. (Dengan banyak replika, tugas replika lain yang dimulai
    sebelum proses ini ikut ditandai gagal; verifikasi murah diulang, jadi tidak diatasi di sini.)"""

    name = "verifikasi"
    required = False

    def __init__(self, db: Database, *, batch: int = 1000) -> None:
        self._db = db
        self._batch = batch
        self._tasks: set[asyncio.Task[None]] = set()
        self._boot: asyncio.Task[None] | None = None
        self._started = datetime.now(UTC)

    async def start(self) -> None:
        self._started = datetime.now(UTC)
        self._boot = asyncio.create_task(self._recover(), name="audit-verify-recover")

    async def _recover(self) -> None:
        await self._db.wait_ready()
        async with self._db.engine.begin() as conn:
            stale = await store.fail_stale_jobs(conn, self._started)
            current = await store.head(conn)
        if current:
            metrics.CHAIN_LENGTH.set(current["seq"])
        if stale:
            log.warning("tugas_verifikasi_tertinggal_ditandai_gagal", jumlah=stale)

    async def stop(self) -> None:
        for task in [self._boot, *self._tasks]:
            if task is not None:
                task.cancel()

    async def check(self) -> Check:
        return Check("ok", f"berjalan={len(self._tasks)}")

    async def submit(self, from_seq: int, to_seq: int | None) -> tuple[str, asyncio.Task[None]]:
        job_id = "ver_" + secrets.token_hex(8)
        async with self._db.engine.begin() as conn:
            await store.insert_job(conn, job_id, from_seq)
        task = asyncio.create_task(self._run(job_id, from_seq, to_seq), name=f"verify-{job_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job_id, task

    async def _run(self, job_id: str, from_seq: int, to_seq: int | None) -> None:
        started = time.perf_counter()
        try:
            async with self._db.engine.connect() as conn:
                result = await store.verify_range(conn, from_seq=from_seq, to_seq=to_seq, batch=self._batch)
            async with self._db.engine.begin() as conn:
                await store.finish_job(conn, job_id, result)
        except asyncio.CancelledError:
            raise  # dihentikan saat layanan berhenti; ditandai gagal pada start berikutnya
        except Exception as exc:  # noqa: BLE001 - kegagalan dicatat di tugas, bukan menjatuhkan layanan
            metrics.VERIFY_FAILED.inc()
            log.exception("tugas_verifikasi_gagal", job_id=job_id)
            try:
                async with self._db.engine.begin() as conn:
                    await store.fail_job(conn, job_id, type(exc).__name__)
            except Exception:  # noqa: BLE001
                log.exception("tugas_verifikasi_gagal_dicatat", job_id=job_id)
            return
        metrics.VERIFY_DURATION.observe(time.perf_counter() - started)
        metrics.VERIFY_TOTAL.labels(str(result["ok"]).lower()).inc()
        log.info("audit_diverifikasi", job_id=job_id, ok=result["ok"], checked=result["checked"])


class AnchorScheduler:
    """Menulis jangkar kepala rantai tiap `interval_min` menit bila kepala berubah. 0 = mati."""

    name = "jangkar"
    required = False

    def __init__(self, db: Database, *, interval_min: int) -> None:
        self._db = db
        self._interval = interval_min * 60
        self._task: asyncio.Task[None] | None = None
        self._last_error: str | None = None

    async def start(self) -> None:
        if self._interval > 0:
            self._task = asyncio.create_task(self._run(), name="audit-anchor")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()

    async def check(self) -> Check:
        if self._interval <= 0:
            return Check("ok", "mati")
        if self._last_error:
            return Check("degraded", f"error={self._last_error}")
        return Check("ok", f"tiap {self._interval // 60} menit")

    async def tick(self) -> dict[str, Any] | None:
        """Satu putaran jangkar. Mengembalikan jangkar baru, atau None bila rantai kosong atau kepala tidak berubah."""
        async with self._db.engine.begin() as conn:
            created = await store.create_anchor(conn)
        if created is None or not created[1]:
            return None
        metrics.ANCHORS_CREATED.inc()
        log.info("jangkar_ditulis", seq=created[0]["seq"])
        return created[0]

    async def _run(self) -> None:
        await self._db.wait_ready()
        while True:
            try:
                await self.tick()
                self._last_error = None
            except Exception as exc:  # noqa: BLE001 - dicoba lagi pada putaran berikutnya
                self._last_error = type(exc).__name__
                log.warning("jangkar_gagal", error=self._last_error)
            await asyncio.sleep(self._interval)
