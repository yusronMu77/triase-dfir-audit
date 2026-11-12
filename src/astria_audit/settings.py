"""Konfigurasi audit dari env `ASTRIA_*`."""

from astria_common.settings import AstriaSettings


class Settings(AstriaSettings):
    service_name: str = "audit"

    reader_services: frozenset[str] = frozenset({"api", "scheduler", "devtools"})
    """Layanan yang boleh membaca, memverifikasi, mengekspor, dan membuat jangkar (nama tanpa `svc:`).
    Dari env berupa daftar JSON, mis. `ASTRIA_READER_SERVICES='["api","scheduler"]'`. `devtools` untuk smoke dev."""

    max_payload_bytes: int = 4096
    """Batas payload kanonik per entri (413 bila lebih)."""

    verify_batch: int = 1000
    """Jumlah entri per kelompok saat verifikasi."""

    anchor_interval_min: int = 60
    """Selang jangkar otomatis (menit); 0 mematikannya. Jangkar hanya ditulis bila kepala rantai berubah."""
