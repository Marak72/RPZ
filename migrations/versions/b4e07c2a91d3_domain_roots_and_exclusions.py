"""Корневые домены и правила исключений

Добавляет threat_domains.root_domain (регистрируемое имя, по нему работает
свёрнутый список) и таблицу правил «не считать вредоносным».

Revision ID: b4e07c2a91d3
Revises: a3d92f1b8c57
Create Date: 2026-08-11
"""
import sqlalchemy as sa
from alembic import op

revision = 'b4e07c2a91d3'
down_revision = 'a3d92f1b8c57'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("threat_domains") as batch:
        batch.add_column(sa.Column("root_domain", sa.String(length=300),
                                   nullable=False, server_default=""))
        batch.create_index("ix_threat_domains_root_domain", ["root_domain"])

    op.create_table(
        "domain_exclusions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("pattern", sa.String(length=300), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False,
                  server_default=""),
        sa.Column("removed_count", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("hits_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("domain_exclusions") as batch:
        batch.create_index("ix_domain_exclusions_pattern", ["pattern"],
                           unique=True)
        batch.create_index("ix_domain_exclusions_created_at", ["created_at"])

    _fill_roots()


def _fill_roots() -> None:
    """Проставить корень уже загруженным доменам.

    Считаем той же функцией, что и приложение: держать вторую реализацию
    правил в миграции — верный способ получить расхождение.
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from app.services.skydns.lib.domains import registrable

    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, domain FROM threat_domains")).fetchall()
    for row in rows:
        bind.execute(
            sa.text("UPDATE threat_domains SET root_domain = :root WHERE id = :id"),
            {"root": registrable(row[1]), "id": row[0]},
        )


def downgrade():
    with op.batch_alter_table("domain_exclusions") as batch:
        batch.drop_index("ix_domain_exclusions_created_at")
        batch.drop_index("ix_domain_exclusions_pattern")
    op.drop_table("domain_exclusions")

    with op.batch_alter_table("threat_domains") as batch:
        batch.drop_index("ix_threat_domains_root_domain")
        batch.drop_column("root_domain")
