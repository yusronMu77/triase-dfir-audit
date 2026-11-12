"""Metrik Prometheus milik audit (didaftarkan sekali per proses)."""

from prometheus_client import Counter, Gauge, Histogram

CHAIN_LENGTH = Gauge("audit_chain_length", "Nomor urut entri terakhir (panjang rantai)")
WRITE_DURATION = Histogram("audit_write_duration_seconds", "Durasi penulisan satu entri (kunci, kepala, hash, sisip)")
RECORDS = Counter("audit_records_total", "Catatan yang diterima", ["via", "result"])
VERIFY_DURATION = Histogram(
    "audit_verify_duration_seconds",
    "Durasi tugas verifikasi",
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 15, 60, 300),
)
VERIFY_TOTAL = Counter("audit_verify_total", "Tugas verifikasi selesai", ["ok"])
VERIFY_FAILED = Counter("audit_verify_jobs_failed_total", "Tugas verifikasi yang gagal dijalankan")
ANCHORS_CREATED = Counter("audit_anchors_created_total", "Jangkar yang ditulis")
