"""Rakit aplikasi audit: migrasi skema, buku besar, jalur sinkron, konsumen, tugas verifikasi, dan jangkar."""

from astria_common.app import create_app
from astria_common.consumer import Consumer, Handler
from astria_common.log import get_logger
from astria_common.service import standard_runtime
from astria_contracts import Envelope
from astria_contracts.events.audit_record import AuditRecord
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_audit import api, workers
from astria_audit.settings import Settings

log = get_logger(__name__)


def make_record_handler(max_payload: int) -> Handler:
    async def on_audit_record(conn: AsyncConnection, envelope: Envelope, data: BaseModel) -> None:
        record = data if isinstance(data, AuditRecord) else AuditRecord.model_validate(data.model_dump())
        entry, duplicate = await workers.append(conn, record, via="event", max_payload=max_payload)
        log.info("audit_tercatat", seq=entry["seq"], action=record.action, via="event", duplicate=duplicate)

    return on_audit_record


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    # Basis data hanya menyiapkan skemanya sendiri dan tabel outbox; tabel audit dibuat migrasi (komponen pertama).
    runtime = standard_runtime(settings)
    if runtime.db is not None and settings.database_url is not None:
        if runtime.db.dialect != "postgresql":
            raise ValueError("audit hanya mendukung PostgreSQL (ASTRIA_DATABASE_URL)")
        runtime.add(
            workers.SkemaMigrator(
                runtime.db,
                url=settings.database_url.get_secret_value(),
                schema=settings.db_schema,
            )
        )
        runtime.add(workers.VerifyRunner(runtime.db, batch=settings.verify_batch))
        runtime.add(workers.AnchorScheduler(runtime.db, interval_min=settings.anchor_interval_min))
    if runtime.db is not None and runtime.bus is not None:
        runtime.add(
            Consumer(
                runtime.bus,
                runtime.db,
                durable="audit",
                event_type="audit.record",
                handler=make_record_handler(settings.max_payload_bytes),
            )
        )
    return create_app(settings, components=runtime.components, routers=[api.router])
