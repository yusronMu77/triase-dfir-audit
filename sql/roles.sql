-- Pemisahan peran basis data untuk audit (bagian Keamanan di notes/2026-11-06-triase-dfir-app-audit.md).
-- Dijalankan SEKALI oleh pemilik basis data (superuser atau pemilik skema), BUKAN oleh layanan, dan hanya
-- setelah migrasi diterapkan (`astria-audit migrate` sebagai pemilik, atau start layanan sekali) supaya tabelnya
-- sudah ada. Ganti :schema dan kata sandi sebelum dipakai.
--
--   psql "$ADMIN_URL" -v schema=audit -f sql/roles.sql
--
-- Gambaran peran:
--   audit_owner   pemilik tabel dan trigger; hanya dipakai untuk migrasi/DDL (`astria-audit migrate`), tidak dipakai layanan.
--   audit_writer  dipakai layanan audit: tambah dan baca entri, jangkar, dan tugas verifikasi. Tidak punya
--                 UPDATE (kecuali verify_jobs, yang memang berstatus), DELETE, atau TRUNCATE pada entries/anchors.
--   audit_reader  hanya baca, untuk pemeriksa/ekspor di luar layanan.
-- Trigger append-only di entries dan anchors tetap menjadi lapis kedua: pemilik tabel pun tidak bisa
-- UPDATE/DELETE/TRUNCATE tanpa mematikan trigger secara eksplisit (ALTER TABLE ... DISABLE TRIGGER),
-- dan tindakan itu terdeteksi oleh verifikasi rantai dan jangkar.
--
-- Kata sandi: isi lewat \password di psql atau pengelola rahasia; jangan menulisnya di berkas ini.

\set ON_ERROR_STOP on

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
        CREATE ROLE audit_writer LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_reader') THEN
        CREATE ROLE audit_reader LOGIN;
    END IF;
END
$$;

-- Layanan memakai skema sendiri (ASTRIA_DB_SCHEMA); kosongkan hak bawaan lalu beri secukupnya.
GRANT USAGE ON SCHEMA :"schema" TO audit_writer, audit_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA :"schema" FROM audit_writer, audit_reader;

-- Riwayat migrasi: layanan hanya membacanya untuk memeriksa bahwa skema sudah di head. Migrasi baru tetap
-- dijalankan pemilik (DDL), jadi layanan dengan peran ini gagal start bila skema belum di head.
GRANT SELECT ON :"schema".alembic_version TO audit_writer, audit_reader;

-- Buku besar dan jangkar: hanya tambah dan baca.
GRANT SELECT, INSERT ON :"schema".entries, :"schema".anchors TO audit_writer;
GRANT SELECT ON :"schema".entries, :"schema".anchors TO audit_reader;

-- Tugas verifikasi: ditulis dan diperbarui statusnya oleh layanan; pembaca hanya melihat.
GRANT SELECT, INSERT, UPDATE ON :"schema".verify_jobs TO audit_writer;
GRANT SELECT ON :"schema".verify_jobs TO audit_reader;

-- Kolom identitas (anchors.anchor_id) memakai sequence internal; INSERT cukup, tanpa hak sequence terpisah.
-- Sengaja TIDAK ada: UPDATE, DELETE, TRUNCATE pada entries dan anchors, serta hak membuat objek.
REVOKE CREATE ON SCHEMA :"schema" FROM audit_writer, audit_reader;

-- Cek cepat (harus kosong untuk entries/anchors):
--   SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants
--    WHERE table_schema = :'schema' AND grantee IN ('audit_writer', 'audit_reader')
--      AND table_name IN ('entries', 'anchors') AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE');
