<!-- astria-logo -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/astria-logo-reverse.svg">
    <img src=".github/assets/astria-logo.svg" alt="Astria" width="320">
  </picture>
</p>

# Astria audit

Buku besar audit berantai hash.

> Status: versi penuh 0.2.0 (kontrak `audit-internal` v0.2.0, contracts v0.4.0). Repo ini adalah submodule dari workspace `triase-dfir` (folder `audit/`). Rancangan: `notes/2026-11-06-triase-dfir-app-audit.md` di repo root. Lajur developer: 3.

## Yang dilakukan

| Fitur | Endpoint atau perintah | Catatan |
|---|---|---|
| Tulis entri | `POST /internal/v1/records` | Semua layanan bertoken sah; idempoten (201 baru, 200 duplikat, 409 isi beda). Konsumen `audit.record` memakai jalur tulis yang sama. |
| Baca entri | `GET /internal/v1/records?actor=&action=&target_type=&target_id=&from_seq=&limit=` | Filter digabung dengan AND, halaman lewat `next_from_seq`. |
| Verifikasi | `POST /internal/v1/verify-jobs`, `GET /internal/v1/verify-jobs/{id}` | Isi opsional `from_seq`, `to_seq`; `?wait_ms=` (bawaan 2000). 200 bila selesai dalam waktu itu, 202 bila masih berjalan. Hasil memuat `anchor_match`. |
| Jangkar | `GET /internal/v1/anchor/latest`, `GET/POST /internal/v1/anchors` | Dibuat otomatis tiap `anchor_interval_min` menit, hanya bila kepala rantai berubah. `POST` 201 baru, 200 bila kepala sama. |
| Ekspor | `GET /internal/v1/export?from_seq=&to_seq=` | JSONL (`application/x-ndjson`), satu entri per baris, kunci terurut, tanpa `request_hash`. Distream per kelompok. |

Rantai: `seq` mulai 1, `prev_hash` entri pertama 64 nol, `entry_hash` = sha256 JSON kanonik
(NFC, kunci terurut, tanpa float) atas semua kolom entri kecuali `payload` dan `entry_hash` (`payload_hash` ikut).
Format ini sama dengan Tahap 0, jadi rantai yang sudah ada tetap valid.

## Otorisasi

Baca, verifikasi, ekspor, dan jangkar hanya untuk layanan di `ASTRIA_READER_SERVICES` (bawaan `api`, `scheduler`,
`devtools`). Bila token membawa klaim `act` (pengguna di balik layanan), perannya juga diperiksa: baca butuh `admin`
atau `dfir`; verifikasi, ekspor, dan buat jangkar butuh `admin`. Penolakan: 403 `PEMANGGIL_DITOLAK` atau `PERAN_TIDAK_CUKUP`.
Menulis tidak dibatasi (semua layanan mencatat audit).

## Verifikasi dan ekspor offline

```text
astria-audit export --out ekspor.jsonl [--from 1] [--to 5000]   # dari basis data (butuh ASTRIA_DATABASE_URL)
astria-audit verify-file ekspor.jsonl                           # tanpa basis data dan tanpa konfigurasi
```

`verify-file` mengembalikan kode 0 (utuh), 1 (rusak; mencetak `seq` pertama yang salah dan alasannya), atau 2 (berkas
tidak terbaca). Ekspor parsial (`--from` > 1) dipercaya pada `prev_hash` entri pertamanya: yang dibuktikan adalah
kesinambungan di dalam berkas, bukan kaitannya ke entri sebelum berkas. Alasan galat: `nomor_urut_berlubang`,
`prev_hash_tidak_cocok`, `payload_hash_tidak_cocok`, `payload_tidak_kanonik`, `entry_hash_tidak_cocok`,
`baris_tidak_valid`, `jangkar_tidak_cocok`.

## Konfigurasi

| Env | Bawaan | Arti |
|---|---|---|
| `ASTRIA_READER_SERVICES` | `["api","scheduler","devtools"]` | Daftar JSON layanan pembaca (tanpa `svc:`). `devtools` untuk smoke dev; hapus di produksi. |
| `ASTRIA_MAX_PAYLOAD_BYTES` | `4096` | Batas payload kanonik per entri (413 bila lebih). |
| `ASTRIA_VERIFY_BATCH` | `1000` | Entri per kelompok saat verifikasi. |
| `ASTRIA_ANCHOR_INTERVAL_MIN` | `60` | Selang jangkar otomatis; `0` mematikannya. |

Metrik: `audit_chain_length`, `audit_write_duration_seconds`, `audit_records_total{via,result}`,
`audit_verify_duration_seconds`, `audit_verify_total{ok}`, `audit_anchors_created_total`.
Tugas verifikasi berstatus `berjalan` sisa proses sebelumnya ditandai `gagal` saat layanan start.

## Peran basis data

[sql/roles.sql](sql/roles.sql) membuat `audit_writer` (INSERT/SELECT pada `entries` dan `anchors`, UPDATE hanya pada
`verify_jobs`) dan `audit_reader` (SELECT). Trigger append-only di `entries` dan `anchors` menjadi lapis kedua.
Layanan membuat tabel saat start, jadi jalankan skrip itu sesudah start pertama, dan jalankan start berikutnya dengan
`audit_writer` hanya bila tabel dan trigger sudah ada (bagian DDL awal memerlukan pemilik). Penerapan di infra masih
dikerjakan manual; belum ada otomasinya.

## Belum dikerjakan

- Enkripsi ekspor dengan age/pyrage (ditunda; ekspor saat ini berupa JSONL polos, simpan di tempat terkendali).
- Penandaan `exported_to` pada jangkar (kolomnya ada, tidak diisi).

## Tech stack

Python 3.14, FastAPI, PostgreSQL 18, NATS JetStream, uv

## Perintah

```text
uv sync                                   # butuh akses ke repo privat contracts dan common (tag git)
uv run ruff format --check . && uv run ruff check .
uv run pytest
sh ../common/template/localtest.sh        # di kontainer py devenv: uji terhadap salinan kerja common dan contracts
```

Menjalankan bersama layanan lain: `pwsh ../devenv/scripts/dev.ps1 up`, lalu `dev.ps1 smoke`.

## Alur git

Branch `{type}/{yyyyMMdd}-{taskId}-{nama}`; commit `{type}({yyyyMMddHHmm}): [{taskId}] {pesan}`, satu baris, tanpa trailer. `main` hanya berubah lewat pull request (merge rebase); jangan push langsung ke `main` dan jangan `--no-verify`.
