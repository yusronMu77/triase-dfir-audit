"""Baseline skema audit: entries, anchors, verify_jobs, indeks, fungsi dan pemicu append-only.

Setara dengan `create_all` Tahap 0 dan 0.2.0 ditambah pemicu. Basis data yang sudah punya tabel ini tidak dibuat
ulang: `astria_audit.skema` menandainya dengan `stamp`. Tidak bisa diturunkan: buku besar hanya boleh ditambah.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-12
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None

# Fungsi dan pemicu append-only di entries dan anchors: UPDATE, DELETE, dan TRUNCATE ditolak.
_FUNGSI_TOLAK_UBAH = """
CREATE OR REPLACE FUNCTION audit_tolak_ubah() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit.% hanya boleh ditambah (%)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
END $$
"""

_PEMICU = (
    "CREATE TRIGGER entries_append_only BEFORE UPDATE OR DELETE ON entries"
    " FOR EACH ROW EXECUTE FUNCTION audit_tolak_ubah()",
    "CREATE TRIGGER entries_no_truncate BEFORE TRUNCATE ON entries"
    " FOR EACH STATEMENT EXECUTE FUNCTION audit_tolak_ubah()",
    "CREATE TRIGGER anchors_append_only BEFORE UPDATE OR DELETE ON anchors"
    " FOR EACH ROW EXECUTE FUNCTION audit_tolak_ubah()",
    "CREATE TRIGGER anchors_no_truncate BEFORE TRUNCATE ON anchors"
    " FOR EACH STATEMENT EXECUTE FUNCTION audit_tolak_ubah()",
)


def upgrade() -> None:
    op.create_table(
        "entries",
        sa.Column("seq", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("via", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("request_hash", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("prev_hash", sa.Text(), nullable=False),
        sa.Column("entry_hash", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("seq"),
    )
    op.create_index("entries_actor_seq", "entries", ["actor", "seq"])
    op.create_index("entries_action_seq", "entries", ["action", "seq"])

    op.create_table(
        "anchors",
        sa.Column("anchor_id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("entry_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("exported_to", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("anchor_id"),
    )
    op.create_index("anchors_seq", "anchors", ["seq"])

    op.create_table(
        "verify_jobs",
        sa.Column("job_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("from_seq", sa.BigInteger(), nullable=False),
        sa.Column("to_seq", sa.BigInteger(), nullable=True),
        sa.Column("checked", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=True),
        sa.Column("first_bad_seq", sa.BigInteger(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("anchor_match", sa.Boolean(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint("status IN ('berjalan','selesai','gagal')", name="verify_jobs_status"),
        sa.PrimaryKeyConstraint("job_id"),
    )

    op.execute(_FUNGSI_TOLAK_UBAH)
    for pemicu in _PEMICU:
        op.execute(pemicu)


def downgrade() -> None:
    raise NotImplementedError("baseline audit tidak diturunkan: buku besar hanya boleh ditambah")
