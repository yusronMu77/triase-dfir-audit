# Changelog

## [Unreleased]

### Changed

- Dependensi `astria-common` naik ke `v0.2.3`, yang menyematkan `astria-contracts` `v0.4.0`. `override-dependencies` di `pyproject.toml` dihapus.
- CI menjalankan uji integrasi PostgreSQL: service `postgres:18.6-alpine` dan `ASTRIA_TEST_DATABASE_URL` pada langkah pytest (sebelumnya uji itu di-skip).

## [0.2.0]

### Added

- Versi penuh sesuai kontrak `audit-internal` v0.2.0 (contracts v0.4.0): otorisasi `reader_services` ditambah peran `act`, filter `GET /records`, tugas verifikasi (`POST/GET /verify-jobs`, `wait_ms` 200/202, verifikasi parsial, `anchor_match`), jangkar (`anchors`, `AnchorScheduler`, `/anchor/latest`, `/anchors`), ekspor JSONL stream (`/export`).
- CLI `astria-audit verify-file` (offline, tanpa basis data) dan `astria-audit export`.
- Metrik audit (`audit_chain_length`, `audit_write_duration_seconds`, `audit_records_total`, `audit_verify_*`, `audit_anchors_created_total`), pengaturan `max_payload_bytes`, `verify_batch`, `anchor_interval_min`, `reader_services`.
- Indeks `entries(actor, seq)` dan `entries(action, seq)`; tabel `anchors` dan `verify_jobs`; `sql/roles.sql` untuk pemisahan peran basis data.
- Uji lengkap: verifier murni, CLI, dan PostgreSQL nyata (tamper di batas kelompok, entri tengah dihapus, dua penulis konkuren, jangkar, tugas basi).

### Changed

- Kode rantai dipecah menjadi paket `astria_audit.chain` (`canonical`, `hashing`, `verifier`, `store`); format rantai Tahap 0 tidak berubah dan API lama tetap diekspor dari `astria_audit.chain`.
- Pesan pemicu append-only menjadi `audit.<tabel> hanya boleh ditambah`; tugas verifikasi sisa proses sebelumnya ditandai `gagal` saat start.
- Dependensi: astria-common v0.2.2 dan astria-contracts v0.4.0 (lewat `override-dependencies` sampai common menyematkan contracts v0.4.0).

## [0.1.0]

### Added

- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Buku besar audit berantai hash: `POST/GET /internal/v1/records` (sinkron, idempoten), `POST /internal/v1/verify-jobs`, konsumen `audit.record`, pemicu append-only.
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
