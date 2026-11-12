"""API internal audit (kontrak: contracts/openapi/audit-internal.yaml, v0.2.0).

Jalur sinkron fail-closed: bila basis data belum siap, jawaban 503 dan penerbit wajib menggagalkan aksinya.
Menulis boleh dari layanan mana pun yang bertoken untuk `svc:audit`. Membaca, verifikasi, ekspor, dan jangkar hanya
dari `reader_services`; token berklaim `act` juga harus berperan `admin` atau `dfir` (baca) atau `admin` (verifikasi,
ekspor, buat jangkar). Peran `act` sudah dibaca ulang identity dari basis datanya saat token diterbitkan.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Annotated, Any

import orjson
from astria_common.auth import ServicePrincipal, require_service
from astria_common.db import Database
from astria_common.errors import AstriaError
from astria_common.log import get_logger
from astria_contracts.events.audit_record import AuditRecord
from astria_contracts.openapi.audit_internal import (
    Anchor,
    AnchorPage,
    RecordPage,
    RecordReceipt,
    VerifyRequest,
    VerifyResult,
)
from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from astria_audit import enkripsi, metrics, workers
from astria_audit.chain import store
from astria_audit.settings import Settings

log = get_logger(__name__)
router = APIRouter(prefix="/internal/v1", tags=["audit"])
caller = require_service("svc:audit")

READ_ROLES = frozenset({"admin", "dfir"})
ADMIN_ROLES = frozenset({"admin"})


def authorize(roles: frozenset[str]) -> Callable[..., Any]:
    """Dependensi: token layanan sah, pemanggil ada di `reader_services`, dan (bila ada `act`) perannya cukup."""

    async def dependency(request: Request, principal: Annotated[ServicePrincipal, Depends(caller)]) -> ServicePrincipal:
        settings: Settings = request.app.state.settings
        if principal.service not in settings.reader_services:
            raise AstriaError("PEMANGGIL_DITOLAK", "layanan ini tidak boleh membaca audit", 403)
        if principal.act is not None:
            held = {r for r in principal.act.get("roles", []) if isinstance(r, str)}
            if not held & roles:
                raise AstriaError("PERAN_TIDAK_CUKUP", "peran pengguna tidak cukup untuk aksi ini", 403)
        return principal

    return dependency


read_access = authorize(READ_ROLES)
admin_access = authorize(ADMIN_ROLES)


def _db(request: Request) -> Database:
    db: Database = request.app.state.components["postgres"]
    if not db.is_ready:
        raise AstriaError("AUDIT_TIDAK_TERSEDIA", "basis data audit belum siap", 503)
    return db


def _settings(request: Request) -> Settings:
    return request.app.state.settings


@router.post("/records", response_model=RecordReceipt, status_code=201)
async def write_record(
    record: AuditRecord,
    request: Request,
    principal: Annotated[ServicePrincipal, Depends(caller)],
) -> JSONResponse:
    db = _db(request)
    try:
        async with db.engine.begin() as conn:
            entry, duplicate = await workers.append(
                conn, record, via="sync", max_payload=_settings(request).max_payload_bytes
            )
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
    _principal: Annotated[ServicePrincipal, Depends(read_access)],
    from_seq: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    actor: Annotated[str | None, Query(max_length=64)] = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    target_type: Annotated[str | None, Query(max_length=64)] = None,
    target_id: Annotated[str | None, Query(max_length=200)] = None,
) -> RecordPage:
    db = _db(request)
    async with db.engine.connect() as conn:
        items, next_from = await store.query_entries(
            conn,
            from_seq=from_seq,
            limit=limit,
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
        )
    return RecordPage.model_validate({"items": items, "next_from_seq": next_from})


# --- verifikasi ---


@router.post("/verify-jobs", response_model=VerifyResult)
async def start_verify(
    request: Request,
    _principal: Annotated[ServicePrincipal, Depends(admin_access)],
    body: VerifyRequest | None = None,
    wait_ms: Annotated[int, Query(ge=0, le=10000)] = 2000,
) -> JSONResponse:
    db = _db(request)
    from_seq = (body.from_seq if body else None) or 1
    to_seq = body.to_seq if body else None
    if to_seq is not None and to_seq < from_seq:
        raise AstriaError("VALIDASI_GAGAL", "to_seq lebih kecil dari from_seq", 400)
    runner: workers.VerifyRunner = request.app.state.components["verifikasi"]
    try:
        job_id, task = await runner.submit(from_seq, to_seq)
    except AstriaError:
        raise
    except Exception as exc:
        log.exception("tugas_verifikasi_gagal_dibuat")
        raise AstriaError("AUDIT_TIDAK_TERSEDIA", "tugas verifikasi tidak dapat dibuat", 503) from exc
    if wait_ms:
        await asyncio.wait({task}, timeout=wait_ms / 1000)
    async with db.engine.connect() as conn:
        job = await store.get_job(conn, job_id)
    if job is None:  # tidak mungkin: baris dibuat sebelum tugas dijalankan
        raise AstriaError("AUDIT_TIDAK_TERSEDIA", "tugas verifikasi hilang", 503)
    result = VerifyResult.model_validate(job)
    return JSONResponse(result.model_dump(mode="json"), status_code=202 if job["status"] == "berjalan" else 200)


@router.get("/verify-jobs/{job_id}", response_model=VerifyResult)
async def get_verify_job(
    job_id: Annotated[str, Path(pattern=r"^ver_[A-Za-z0-9]+$")],
    request: Request,
    _principal: Annotated[ServicePrincipal, Depends(read_access)],
) -> VerifyResult:
    db = _db(request)
    async with db.engine.connect() as conn:
        job = await store.get_job(conn, job_id)
    if job is None:
        raise AstriaError("TUGAS_TIDAK_DITEMUKAN", "tugas verifikasi tidak ditemukan", 404)
    return VerifyResult.model_validate(job)


# --- ekspor ---


async def _export_stream(db: Database, from_seq: int, to_seq: int | None) -> AsyncIterator[bytes]:
    async with db.engine.connect() as conn:
        async for entry in store.iter_entries(conn, from_seq=from_seq, to_seq=to_seq):
            yield orjson.dumps(entry, option=orjson.OPT_SORT_KEYS) + b"\n"


@router.get("/export")
async def export_records(
    request: Request,
    _principal: Annotated[ServicePrincipal, Depends(admin_access)],
    from_seq: Annotated[int, Query(ge=1)] = 1,
    to_seq: Annotated[int | None, Query(ge=1)] = None,
    recipient: Annotated[list[str] | None, Query()] = None,
) -> Response:
    """Ekspor JSONL. Dengan `recipient` (berulang, kunci publik age), isi dienkripsi ke penerima itu dan dikirim
    sebagai `application/age`. Bila `ASTRIA_EXPORT_AGE_RECIPIENTS` diatur, ekspor selalu terenkripsi: tanpa
    `recipient` atau dengan penerima di luar daftar, jawabannya 400."""
    db = _db(request)
    if to_seq is not None and to_seq < from_seq:
        raise AstriaError("VALIDASI_GAGAL", "to_seq lebih kecil dari from_seq", 400)
    penerima = enkripsi.resolve_recipients(_settings(request).export_age_recipients, recipient or [])
    if not penerima:
        log.info("audit_diekspor", from_seq=from_seq, to_seq=to_seq, terenkripsi=False)
        return StreamingResponse(_export_stream(db, from_seq, to_seq), media_type="application/x-ndjson")
    isi = b"".join([chunk async for chunk in _export_stream(db, from_seq, to_seq)])
    blob = enkripsi.encrypt_bytes(isi, penerima)
    log.info("audit_diekspor", from_seq=from_seq, to_seq=to_seq, terenkripsi=True, penerima=len(penerima))
    berkas = f"audit-{from_seq}-{to_seq or 'akhir'}.jsonl.age"
    return Response(
        blob, media_type="application/age", headers={"Content-Disposition": f'attachment; filename="{berkas}"'}
    )


# --- jangkar ---


@router.get("/anchor/latest", response_model=Anchor)
async def latest_anchor(request: Request, _principal: Annotated[ServicePrincipal, Depends(read_access)]) -> Anchor:
    db = _db(request)
    async with db.engine.connect() as conn:
        anchor = await store.latest_anchor(conn)
    if anchor is None:
        raise AstriaError("JANGKAR_BELUM_ADA", "belum ada jangkar", 404)
    return Anchor.model_validate(anchor)


@router.get("/anchors", response_model=AnchorPage)
async def list_anchors(
    request: Request,
    _principal: Annotated[ServicePrincipal, Depends(read_access)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AnchorPage:
    db = _db(request)
    async with db.engine.connect() as conn:
        items = await store.list_anchors(conn, limit)
    return AnchorPage.model_validate({"items": items})


@router.post("/anchors", response_model=Anchor, status_code=201)
async def create_anchor(
    request: Request, _principal: Annotated[ServicePrincipal, Depends(admin_access)]
) -> JSONResponse:
    """Jangkar kepala rantai sekarang. 201 untuk jangkar baru; 200 bila kepala sama dengan jangkar terakhir."""
    db = _db(request)
    async with db.engine.begin() as conn:
        created = await store.create_anchor(conn)
    if created is None:
        raise AstriaError("RANTAI_KOSONG", "rantai audit masih kosong", 404)
    anchor, is_new = created
    if is_new:
        metrics.ANCHORS_CREATED.inc()
    return JSONResponse(Anchor.model_validate(anchor).model_dump(mode="json"), status_code=201 if is_new else 200)
