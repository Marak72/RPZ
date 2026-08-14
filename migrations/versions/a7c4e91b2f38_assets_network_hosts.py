"""Сервис «Узлы сети»: адреса, компьютеры AD, области DHCP и журналы.

Новые таблицы, существующих не трогаем — миграция полностью обратима и
безопасна для боевой базы: ни одна прежняя запись не читается и не меняется.

Revision ID: a7c4e91b2f38
Revises: e3f86b6be9f3
Create Date: 2026-08-14

"""
from alembic import op
import sqlalchemy as sa

revision = "a7c4e91b2f38"
down_revision = "e3f86b6be9f3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "asset_ad_computers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("fqdn", sa.String(length=255), nullable=False,
                  server_default=""),
        sa.Column("dn", sa.Text(), nullable=False, server_default=""),
        sa.Column("ou_path", sa.String(length=500), nullable=False,
                  server_default=""),
        sa.Column("description", sa.String(length=1000), nullable=False,
                  server_default=""),
        sa.Column("os", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("os_version", sa.String(length=100), nullable=False,
                  server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("managed_by", sa.Text(), nullable=False, server_default=""),
        sa.Column("last_logon", sa.DateTime(), nullable=True),
        sa.Column("when_created", sa.DateTime(), nullable=True),
        sa.Column("kind", sa.String(length=20), nullable=False,
                  server_default="unknown"),
        sa.Column("synced_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_ad_computers_name", "asset_ad_computers",
                    ["name"], unique=True)
    op.create_index("ix_asset_ad_computers_ou_path", "asset_ad_computers",
                    ["ou_path"])
    op.create_index("ix_asset_ad_computers_kind", "asset_ad_computers", ["kind"])
    op.create_index("ix_asset_ad_computers_synced_at", "asset_ad_computers",
                    ["synced_at"])

    op.create_table(
        "asset_hosts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("ip_int", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("hostname", sa.String(length=255), nullable=False,
                  server_default=""),
        sa.Column("mac", sa.String(length=17), nullable=False, server_default=""),
        sa.Column("dhcp_server", sa.String(length=255), nullable=False,
                  server_default=""),
        sa.Column("scope_id", sa.String(length=45), nullable=False,
                  server_default=""),
        sa.Column("lease_state", sa.String(length=40), nullable=False,
                  server_default=""),
        sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(length=20), nullable=False,
                  server_default="dhcp"),
        sa.Column("kind", sa.String(length=20), nullable=False,
                  server_default="unknown"),
        sa.Column("ad_computer_id", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["ad_computer_id"], ["asset_ad_computers.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_hosts_ip", "asset_hosts", ["ip"], unique=True)
    op.create_index("ix_asset_hosts_ip_int", "asset_hosts", ["ip_int"])
    op.create_index("ix_asset_hosts_hostname", "asset_hosts", ["hostname"])
    op.create_index("ix_asset_hosts_mac", "asset_hosts", ["mac"])
    op.create_index("ix_asset_hosts_scope_id", "asset_hosts", ["scope_id"])
    op.create_index("ix_asset_hosts_source", "asset_hosts", ["source"])
    op.create_index("ix_asset_hosts_kind", "asset_hosts", ["kind"])
    op.create_index("ix_asset_hosts_ad_computer_id", "asset_hosts",
                    ["ad_computer_id"])
    op.create_index("ix_asset_hosts_last_seen", "asset_hosts", ["last_seen"])

    op.create_table(
        "asset_observations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("seen_at", sa.DateTime(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=False,
                  server_default=""),
        sa.Column("mac", sa.String(length=17), nullable=False, server_default=""),
        sa.Column("lease_state", sa.String(length=40), nullable=False,
                  server_default=""),
        sa.Column("change", sa.String(length=500), nullable=False,
                  server_default=""),
        sa.ForeignKeyConstraint(["host_id"], ["asset_hosts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_observations_host_id", "asset_observations",
                    ["host_id"])
    op.create_index("ix_asset_observations_seen_at", "asset_observations",
                    ["seen_at"])

    op.create_table(
        "asset_dhcp_scopes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("server", sa.String(length=255), nullable=False),
        sa.Column("scope_id", sa.String(length=45), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False,
                  server_default=""),
        sa.Column("mask", sa.String(length=45), nullable=False, server_default=""),
        sa.Column("start_ip", sa.String(length=45), nullable=False,
                  server_default=""),
        sa.Column("end_ip", sa.String(length=45), nullable=False,
                  server_default=""),
        sa.Column("start_int", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("end_int", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("state", sa.String(length=40), nullable=False,
                  server_default=""),
        sa.Column("lease_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("synced_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("server", "scope_id", name="uq_asset_scope"),
    )
    op.create_index("ix_asset_dhcp_scopes_server", "asset_dhcp_scopes", ["server"])
    op.create_index("ix_asset_dhcp_scopes_start_int", "asset_dhcp_scopes",
                    ["start_int"])
    op.create_index("ix_asset_dhcp_scopes_end_int", "asset_dhcp_scopes",
                    ["end_int"])

    op.create_table(
        "asset_lookups",
        sa.Column("id", sa.Integer(), nullable=False),
        # Не "query": во Flask-SQLAlchemy это имя занято самим Model.query,
        # и колонка с таким именем ломает любой запрос к таблице.
        sa.Column("term", sa.String(length=255), nullable=False),
        sa.Column("query_kind", sa.String(length=20), nullable=False,
                  server_default="text"),
        sa.Column("is_live", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("found", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("result", sa.String(length=500), nullable=False,
                  server_default=""),
        sa.Column("error", sa.String(length=1000), nullable=False,
                  server_default=""),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["host_id"], ["asset_hosts.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_lookups_term", "asset_lookups", ["term"])
    op.create_index("ix_asset_lookups_host_id", "asset_lookups", ["host_id"])
    op.create_index("ix_asset_lookups_user_id", "asset_lookups", ["user_id"])
    op.create_index("ix_asset_lookups_created_at", "asset_lookups", ["created_at"])

    op.create_table(
        "asset_sync_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("servers", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scopes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_sync_logs_source", "asset_sync_logs", ["source"])
    op.create_index("ix_asset_sync_logs_started_at", "asset_sync_logs",
                    ["started_at"])


def downgrade():
    op.drop_table("asset_sync_logs")
    op.drop_table("asset_lookups")
    op.drop_table("asset_dhcp_scopes")
    op.drop_table("asset_observations")
    op.drop_table("asset_hosts")
    op.drop_table("asset_ad_computers")
