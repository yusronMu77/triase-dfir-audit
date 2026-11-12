"""Enkripsi ekspor audit ke penerima age (format age v1) lewat pustaka `pyrage`.

Pilihan pustaka: `pyrage` (github.com/woodruffw/pyrage, rilis 1.4.0 pada 2026-08-23) membungkus implementasi
Rust `age`; dipelihara aktif, wheel tersedia untuk Linux dan Windows, dan hanya bergantung pada PyPI. Alternatif
`age` (pure Python, Jonas Lieb) tidak dipilih karena kurang aktif dan lebih lambat.

Penerima dan identity hanya berupa kunci publik `age1...` dan kunci rahasia `AGE-SECRET-KEY-1...`. Kunci rahasia
tidak pernah masuk ke log atau pesan galat.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pyrage
from astria_common.errors import AstriaError
from pyrage import x25519

AGE_MAGIC = b"age-encryption.org/v1\n"
MAX_RECIPIENTS = 10
MAX_RECIPIENT_LEN = 200
GALAT_AGE = (pyrage.DecryptError, pyrage.IdentityError, pyrage.RecipientError)


def resolve_recipients(configured: Iterable[str], requested: Iterable[str]) -> list[str]:
    """Penerima yang dipakai untuk satu ekspor. Kosong = ekspor polos (hanya bila operator tidak mewajibkan enkripsi).

    Bila `configured` tidak kosong, ekspor wajib terenkripsi: `requested` tidak boleh kosong dan harus berasal dari
    `configured`. Penolakan memakai 400 dengan kode tetap supaya pemanggil tahu sebabnya."""
    allowed = tuple(configured)
    diminta = list(dict.fromkeys(requested))
    if len(diminta) > MAX_RECIPIENTS:
        raise AstriaError("VALIDASI_GAGAL", f"penerima melebihi {MAX_RECIPIENTS}", 400)
    if allowed:
        if not diminta:
            raise AstriaError(
                "EKSPOR_WAJIB_TERENKRIPSI", "ekspor wajib terenkripsi: sertakan recipient age yang diizinkan", 400
            )
        if any(r not in allowed for r in diminta):
            raise AstriaError("PENERIMA_TIDAK_DIIZINKAN", "penerima tidak ada dalam daftar yang diizinkan", 400)
    for recipient in diminta:
        _recipient(recipient)
    return diminta


def _recipient(text: str) -> x25519.Recipient:
    if len(text) > MAX_RECIPIENT_LEN:
        raise AstriaError("VALIDASI_GAGAL", "penerima age tidak valid", 400)
    try:
        return x25519.Recipient.from_str(text)
    except pyrage.RecipientError as exc:
        raise AstriaError("VALIDASI_GAGAL", "penerima age tidak valid", 400) from exc


def encrypt_bytes(data: bytes, recipients: list[str]) -> bytes:
    """Enkripsi seluruh isi (dimuat di memori; ekspor terenkripsi dibatasi rentang seq oleh pemanggil)."""
    return pyrage.encrypt(data, [_recipient(r) for r in recipients])


def load_identities(path: Path) -> list[x25519.Identity]:
    """Baca kunci rahasia dari berkas gaya `age-keygen` (baris `AGE-SECRET-KEY-1...`; baris lain diabaikan)."""
    identities = [
        x25519.Identity.from_str(line.strip())
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("AGE-SECRET-KEY-")
    ]
    if not identities:
        raise ValueError("berkas identity tidak berisi AGE-SECRET-KEY-")
    return identities


def decrypt_bytes(data: bytes, identities: list[x25519.Identity]) -> bytes:
    return pyrage.decrypt(data, identities)
