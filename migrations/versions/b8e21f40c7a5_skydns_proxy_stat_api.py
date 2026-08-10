"""Справочник категорий SkyDNS и источник конечного хоста.

Revision ID: b8e21f40c7a5
Revises: a1c7f3d90e42
Create Date: 2026-08-10
"""
import sqlalchemy as sa
from alembic import op

revision = 'b8e21f40c7a5'
down_revision = 'a1c7f3d90e42'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'skydns_categories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False,
                  server_default=''),
        sa.Column('is_dangerous', sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column('track_override', sa.Boolean(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('skydns_categories') as batch:
        batch.create_index(batch.f('ix_skydns_categories_is_dangerous'),
                           ['is_dangerous'], unique=False)

    with op.batch_alter_table('threat_domains') as batch:
        batch.add_column(sa.Column('cat_ids', sa.String(length=200),
                                   nullable=False, server_default=''))

    with op.batch_alter_table('threat_hosts') as batch:
        batch.add_column(sa.Column('source', sa.String(length=20),
                                   nullable=False, server_default='siem'))
        batch.add_column(sa.Column('device_token', sa.String(length=40),
                                   nullable=False, server_default=''))
        batch.create_index(batch.f('ix_threat_hosts_source'), ['source'],
                           unique=False)


def downgrade():
    with op.batch_alter_table('threat_hosts') as batch:
        batch.drop_index(batch.f('ix_threat_hosts_source'))
        batch.drop_column('device_token')
        batch.drop_column('source')

    with op.batch_alter_table('threat_domains') as batch:
        batch.drop_column('cat_ids')

    op.drop_table('skydns_categories')
