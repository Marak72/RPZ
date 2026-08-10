"""Счётчики по категориям SkyDNS.

Revision ID: f2a91d6e8c04
Revises: e7b420c9d3f1
Create Date: 2026-08-10
"""
import sqlalchemy as sa
from alembic import op

revision = 'f2a91d6e8c04'
down_revision = 'e7b420c9d3f1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('skydns_categories') as batch:
        batch.add_column(sa.Column('requests', sa.Integer(), nullable=False,
                                   server_default='0'))
        batch.add_column(sa.Column('blocks', sa.Integer(), nullable=False,
                                   server_default='0'))
        batch.add_column(sa.Column('domains_count', sa.Integer(), nullable=False,
                                   server_default='0'))


def downgrade():
    with op.batch_alter_table('skydns_categories') as batch:
        batch.drop_column('domains_count')
        batch.drop_column('blocks')
        batch.drop_column('requests')
