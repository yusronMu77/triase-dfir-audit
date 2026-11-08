"""API internal audit Tahap 0 (kontrak: contracts/openapi/audit-internal.yaml).

Jalur sinkron fail-closed: bila basis data belum siap, jawaban 503 dan penerbit wajib menggagalkan aksinya.
"""

from __future__ import annotations

from astria_common.auth import ServicePrincipal, require_service
from astria_common.db import Database
from astria_common.errors import AstriaError
from astria_common.log import get_logger
from astria_contracts.events.audit_record import AuditRecord
from astria_contracts.openapi.audit_internal import RecordPage, RecordReceipt, VerifyResult
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from astria_audit import chain

log = get_logger(__name__)
router = APIRouter(prefix="/internal/v1", tags=["audit"])
caller = require_service("svc:audit")


def _db(request: Request) -> Database:
    db: Database = request.app.state.components["postgres"]
    if not db.is_ready:
        raise AstriaError("AUDIT_TIDAK_TERSEDIA", "basis data audit belum siap", 503)
    return db


@router.post("/records", response_model=RecordReceipt, status_code=201)
async def write_record(
    record: AuditRecord,
    request: Request,
    principal: ServicePrincipal = Depends(caller),  # noqa: B008
) -> JSONResponse:
    db = _db(request)
    try:
        async with db.engine.begin() as conn:
            entry, duplicate = await chain.write(conn, record)
    except AstriaError:
        raise
    except Exception as exc:
        log.exception("audit_gagal_menulis")
        raise AstriaError("AUDIT_TIDAK_TERSEDIA", "audit tidak dapat mencatat", 503) from exc
    log.info(
        "audit_tercatat",
        seq=entry["seq"],
        action=record.action,
        via="sync",
        caller=principal.subject,
        duplicate=duplicate,
    )
    receipt = RecordReceipt(
        seq=entry["seq"], entry_hash=entry["entry_hash"], recorded_at=entry["recorded_at"], duplicate=duplicate
    )
    return JSONResponse(receipt.model_dump(mode="json"), status_code=200 if duplicate else 201)


@router.get("/records", response_model=RecordPage)
async def list_records(
    request: Request,
    from_seq: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    _principal: ServicePrincipal = Depends(caller),  # noqa: B008
) -> RecordPage:
    db = _db(request)
    async with db.engine.connect() as conn:
        rows = (
            (
                await conn.execute(
                    select(chain.entries)
                    .where(chain.entries.c.seq >= from_seq)
                    .order_by(chain.entries.c.seq)
                    .limit(limit + 1)
                )
            )
            .mappings()
            .all()
        )
    items = [chain.row_to_entry(r) for r in rows[:limit]]
    next_from = rows[limit]["seq"] if len(rows) > limit else None
    return RecordPage.model_validate({"items": items, "next_from_seq": next_from})


@router.post("/verify-jobs", response_model=VerifyResult)
async def verify_chain(request: Request, _principal: ServicePrincipal = Depends(caller)) -> VerifyResult:  # noqa: B008
    db = _db(request)
    async with db.engine.connect() as conn:
        result = await chain.verify(conn)
    log.info("audit_diverifikasi", ok=result["ok"], checked=result["checked"])
    return VerifyResult.model_validate(result)
