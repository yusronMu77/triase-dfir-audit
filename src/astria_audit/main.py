"""Rakit aplikasi audit Tahap 0: buku besar berantai hash, jalur sinkron, dan konsumen `audit.record`."""

from astria_common.app import create_app
from astria_common.consumer import Consumer
from astria_common.log import get_logger
from astria_common.service import standard_runtime
from astria_contracts import Envelope
from astria_contracts.events.audit_record import AuditRecord
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_audit import api, chain
from astria_audit.settings import Settings

log = get_logger(__name__)


async def on_audit_record(conn: AsyncConnection, envelope: Envelope, data: BaseModel) -> None:
    record = data if isinstance(data, AuditRecord) else AuditRecord.model_validate(data.model_dump())
    entry, duplicate = await chain.write(conn, record)
    log.info("audit_tercatat", seq=entry["seq"], action=record.action, via="event", duplicate=duplicate)


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    runtime = standard_runtime(settings, metadata=[chain.metadata], setup_sql=chain.SETUP_SQL)
    if runtime.db is not None and runtime.bus is not None:
        runtime.add(
            Consumer(runtime.bus, runtime.db, durable="audit", event_type="audit.record", handler=on_audit_record)
        )
    return create_app(settings, components=runtime.components, routers=[api.router])
