"""Buku besar audit berantai hash.

- `canonical`, `hashing`, `verifier`: logika murni tanpa I/O (dipakai juga CLI offline).
- `store`: bentuk tabel (DDL ada di migrasi), penulis tunggal, baca, verifikasi rentang, jangkar, tugas verifikasi.

Paket ini mengekspos ulang API Tahap 0 (`chain.write`, `chain.verify`, `chain.entries`, ...).
"""

from astria_audit.chain.canonical import FORBIDDEN_KEYS, NotCanonical, canonical, normalize, sha256_hex
from astria_audit.chain.hashing import GENESIS_PREV, entry_hash, fmt_ts
from astria_audit.chain.store import (
    LOCK_KEY,
    MAX_PAYLOAD_BYTES,
    anchors,
    entries,
    metadata,
    request_fingerprint,
    row_to_entry,
    verify,
    verify_jobs,
    write,
)

__all__ = [
    "FORBIDDEN_KEYS",
    "GENESIS_PREV",
    "LOCK_KEY",
    "MAX_PAYLOAD_BYTES",
    "NotCanonical",
    "anchors",
    "canonical",
    "entries",
    "entry_hash",
    "fmt_ts",
    "metadata",
    "normalize",
    "request_fingerprint",
    "row_to_entry",
    "sha256_hex",
    "verify",
    "verify_jobs",
    "write",
]
