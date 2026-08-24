"""Адреса электронной почты как отдельный индикатор.

Раньше из письма брался ДОМЕН адреса отправителя и уезжал в кандидаты на
блокировку. Это опасно: фишинг рассылают с mail.ru и gmail.com, и выгрузка
такого домена в RPZ закрыла бы отделу почту целиком. Теперь адрес хранится
целиком, а его домен блокируется только по решению аналитика.

Новая таблица, существующих не трогаем — миграция полностью обратима.

Revision ID: c8b3f1a45d92
Revises: a7c4e91b2f38
Create Date: 2026-08-24

"""
from alembic import op
import sqlalchemy as sa

revision = "c8b3f1a45d92"
down_revision = "a7c4e91b2f38"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "email_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("value", sa.String(length=320), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False,
                  server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("added_by", sa.Integer(), nullable=True),
        sa.Column("notes", sa.String(length=500), nullable=True,
                  server_default=""),
        sa.ForeignKeyConstraint(["added_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_email_entries_value", "email_entries", ["value"],
                    unique=True)
    op.create_index("ix_email_entries_host", "email_entries", ["host"])
    op.create_index("ix_email_entries_created_at", "email_entries",
                    ["created_at"])

    op.create_table(
        "email_entry_letters",
        sa.Column("entry_id", sa.Integer(), nullable=False),
        sa.Column("letter_id", sa.Integer(), nullable=False),
        sa.Column("file_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["entry_id"], ["email_entries.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["letter_id"], ["letters.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["file_id"], ["letter_files.id"],
                                ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("entry_id", "letter_id"),
    )


def downgrade():
    op.drop_table("email_entry_letters")
    op.drop_table("email_entries")
