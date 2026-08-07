"""Сервис «Угрозы SkyDNS»: домены, конечные хосты и журналы запросов.

Revision ID: a1c7f3d90e42
Revises: b947ab6b927b
Create Date: 2026-08-07
"""
import sqlalchemy as sa
from alembic import op

revision = 'a1c7f3d90e42'
down_revision = 'b947ab6b927b'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'threat_domains',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('domain', sa.String(length=500), nullable=False),
        sa.Column('category', sa.String(length=120), nullable=False,
                  server_default=''),
        sa.Column('category_title', sa.String(length=200), nullable=False,
                  server_default=''),
        sa.Column('profile', sa.String(length=200), nullable=False,
                  server_default=''),
        sa.Column('requests_count', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('blocks_count', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False,
                  server_default='new'),
        sa.Column('source', sa.String(length=20), nullable=False,
                  server_default='api'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('siem_checked_at', sa.DateTime(), nullable=True),
        sa.Column('siem_hosts_count', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('added_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['added_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('threat_domains') as batch:
        # Уникальность домена обеспечивает сам индекс — как в block_entries.value.
        batch.create_index(batch.f('ix_threat_domains_domain'), ['domain'],
                           unique=True)
        batch.create_index(batch.f('ix_threat_domains_category'), ['category'],
                           unique=False)
        batch.create_index(batch.f('ix_threat_domains_status'), ['status'],
                           unique=False)
        batch.create_index(batch.f('ix_threat_domains_first_seen'), ['first_seen'],
                           unique=False)
        batch.create_index(batch.f('ix_threat_domains_last_seen'), ['last_seen'],
                           unique=False)

    op.create_table(
        'threat_hosts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('threat_id', sa.Integer(), nullable=False),
        sa.Column('address', sa.String(length=255), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False,
                  server_default=''),
        sa.Column('events_count', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('found_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['threat_id'], ['threat_domains.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('threat_id', 'address', name='uq_threat_host'),
    )
    with op.batch_alter_table('threat_hosts') as batch:
        batch.create_index(batch.f('ix_threat_hosts_threat_id'), ['threat_id'],
                           unique=False)
        batch.create_index(batch.f('ix_threat_hosts_address'), ['address'],
                           unique=False)
        batch.create_index(batch.f('ix_threat_hosts_found_at'), ['found_at'],
                           unique=False)

    op.create_table(
        'siem_query_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('threat_id', sa.Integer(), nullable=True),
        sa.Column('domain', sa.String(length=500), nullable=False,
                  server_default=''),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False,
                  server_default='success'),
        sa.Column('hosts_found', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('events_total', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('query_filter', sa.Text(), nullable=True),
        sa.Column('period_from', sa.DateTime(), nullable=True),
        sa.Column('period_to', sa.DateTime(), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['threat_id'], ['threat_domains.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('siem_query_logs') as batch:
        batch.create_index(batch.f('ix_siem_query_logs_threat_id'), ['threat_id'],
                           unique=False)
        batch.create_index(batch.f('ix_siem_query_logs_started_at'), ['started_at'],
                           unique=False)

    op.create_table(
        'skydns_sync_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False,
                  server_default='success'),
        sa.Column('source', sa.String(length=20), nullable=False,
                  server_default='api'),
        sa.Column('period_from', sa.Date(), nullable=True),
        sa.Column('period_to', sa.Date(), nullable=True),
        sa.Column('domains_total', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('domains_new', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('skydns_sync_logs') as batch:
        batch.create_index(batch.f('ix_skydns_sync_logs_started_at'), ['started_at'],
                           unique=False)


def downgrade():
    op.drop_table('skydns_sync_logs')
    op.drop_table('siem_query_logs')
    op.drop_table('threat_hosts')
    op.drop_table('threat_domains')
