"""Фоновые задания портала

Поиск хостов в SIEM и выгрузка из SkyDNS уезжают из обработчика запроса
в фоновый поток; их состояние хранится здесь, чтобы прогресс был виден
из любого рабочего процесса.

Revision ID: a3d92f1b8c57
Revises: f2a91d6e8c04
Create Date: 2026-08-11
"""
import sqlalchemy as sa
from alembic import op

revision = 'a3d92f1b8c57'
down_revision = 'f2a91d6e8c04'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "background_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("service_id", sa.String(length=40), nullable=False,
                  server_default=""),
        sa.Column("title", sa.String(length=200), nullable=False,
                  server_default=""),
        sa.Column("status", sa.String(length=20), nullable=False,
                  server_default="queued"),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("result_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detail", sa.String(length=300), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("target_url", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(), nullable=True),
        sa.Column("dismissed_at", sa.DateTime(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("background_jobs") as batch:
        batch.create_index("ix_background_jobs_kind", ["kind"])
        batch.create_index("ix_background_jobs_status", ["status"])
        batch.create_index("ix_background_jobs_created_at", ["created_at"])
        batch.create_index("ix_background_jobs_user_id", ["user_id"])


def downgrade():
    with op.batch_alter_table("background_jobs") as batch:
        batch.drop_index("ix_background_jobs_user_id")
        batch.drop_index("ix_background_jobs_created_at")
        batch.drop_index("ix_background_jobs_status")
        batch.drop_index("ix_background_jobs_kind")
    op.drop_table("background_jobs")
