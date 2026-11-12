"""Verifikasi rantai (modul murni, tanpa basis data dan tanpa jaringan).

Dipakai server (tugas verifikasi) dan CLI offline `verify-file` dengan kode yang sama. Verifier bertahap:
`ChainVerifier.check(entry)` memeriksa satu entri berurutan dan menjaga status (`prev_hash`, `seq` berikutnya).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import orjson

from astria_audit.chain.canonical import NotCanonical, canonical, sha256_hex
from astria_audit.chain.hashing import ENTRY_HASH_FIELDS, GENESIS_PREV, entry_hash

SEQ_BERLUBANG = "nomor_urut_berlubang"
PREV_TIDAK_COCOK = "prev_hash_tidak_cocok"
PAYLOAD_HASH_TIDAK_COCOK = "payload_hash_tidak_cocok"
PAYLOAD_TIDAK_KANONIK = "payload_tidak_kanonik"
ENTRY_HASH_TIDAK_COCOK = "entry_hash_tidak_cocok"
BARIS_TIDAK_VALID = "baris_tidak_valid"
JANGKAR_TIDAK_COCOK = "jangkar_tidak_cocok"

REQUIRED_FIELDS = (*ENTRY_HASH_FIELDS, "payload", "entry_hash")


class ChainVerifier:
    """Memeriksa entri berurutan naik mulai dari `expected_seq`; `prev_hash` menjadi prev_hash yang diharapkan."""

    def __init__(self, *, prev_hash: str = GENESIS_PREV, expected_seq: int = 1) -> None:
        self.prev_hash = prev_hash
        self.expected_seq = expected_seq
        self.checked = 0
        self.last_seq: int | None = None

    def check(self, entry: dict[str, Any]) -> str | None:
        """None bila entri sah (status maju); alasan bila rusak (status tidak berubah)."""
        reason = self._reason(entry)
        if reason is not None:
            return reason
        self.prev_hash = entry["entry_hash"]
        self.last_seq = entry["seq"]
        self.expected_seq += 1
        self.checked += 1
        return None

    def _reason(self, entry: dict[str, Any]) -> str | None:
        if entry["seq"] != self.expected_seq:
            return SEQ_BERLUBANG
        if entry["prev_hash"] != self.prev_hash:
            return PREV_TIDAK_COCOK
        try:
            payload_hash = sha256_hex(canonical(entry["payload"]))
        except NotCanonical:
            return PAYLOAD_TIDAK_KANONIK
        if payload_hash != entry["payload_hash"]:
            return PAYLOAD_HASH_TIDAK_COCOK
        try:
            recomputed = entry_hash(entry)
        except NotCanonical:  # field entri berisi tipe yang tidak bisa dikanonikkan (mis. angka pecahan)
            return ENTRY_HASH_TIDAK_COCOK
        if recomputed != entry["entry_hash"]:
            return ENTRY_HASH_TIDAK_COCOK
        return None


@dataclass(frozen=True)
class FileResult:
    ok: bool
    checked: int
    from_seq: int | None
    to_seq: int | None
    first_bad_seq: int | None = None
    reason: str | None = None
    detail: str | None = None


def verify_lines(lines: Iterable[bytes | str]) -> FileResult:
    """Verifikasi isi berkas ekspor JSONL. Entri pertama menentukan titik awal: bila seq=1, prev_hash harus 64 nol;
    bila ekspor parsial (seq>1), prev_hash entri pertama dipercaya apa adanya (tidak ada pembanding di berkas)."""
    verifier: ChainVerifier | None = None
    from_seq: int | None = None
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            entry = orjson.loads(raw)
        except orjson.JSONDecodeError:
            return FileResult(
                False, _checked(verifier), from_seq, _last(verifier), None, BARIS_TIDAK_VALID, f"baris {number}"
            )
        problem = _shape_problem(entry)
        if problem:
            return FileResult(
                False,
                _checked(verifier),
                from_seq,
                _last(verifier),
                None,
                BARIS_TIDAK_VALID,
                f"baris {number}: {problem}",
            )
        if verifier is None:
            from_seq = entry["seq"]
            start_prev = GENESIS_PREV if entry["seq"] == 1 else entry["prev_hash"]
            verifier = ChainVerifier(prev_hash=start_prev, expected_seq=entry["seq"])
        reason = verifier.check(entry)
        if reason is not None:
            return FileResult(
                False, verifier.checked, from_seq, verifier.last_seq, entry["seq"], reason, f"baris {number}"
            )
    return FileResult(True, _checked(verifier), from_seq, _last(verifier))


def _checked(verifier: ChainVerifier | None) -> int:
    return verifier.checked if verifier else 0


def _last(verifier: ChainVerifier | None) -> int | None:
    return verifier.last_seq if verifier else None


def _shape_problem(entry: Any) -> str | None:
    if not isinstance(entry, dict):
        return "bukan objek"
    missing = [k for k in REQUIRED_FIELDS if k not in entry]
    if missing:
        return "field hilang: " + ", ".join(missing)
    if not isinstance(entry["seq"], int) or isinstance(entry["seq"], bool) or entry["seq"] < 1:
        return "seq tidak valid"
    if not isinstance(entry["payload"], dict):
        return "payload bukan objek"
    return None
