"""Пункты выполнения задачи и отметка просмотра изменений.

Revision ID: e7b420c9d3f1
Revises: d51c8a4e7f26
Create Date: 2026-08-10
"""
import sqlalchemy as sa
from alembic import op

revision = 'e7b420c9d3f1'
down_revision = 'd51c8a4e7f26'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'task_checklist',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('task_id', sa.Integer(), nullable=False),
        sa.Column('text', sa.String(length=500), nullable=False,
                  server_default=''),
        sa.Column('is_done', sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('done_at', sa.DateTime(), nullable=True),
        sa.Column('done_by_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['task_id'], ['tasks.id']),
        sa.ForeignKeyConstraint(['done_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('task_checklist') as batch:
        batch.create_index(batch.f('ix_task_checklist_task_id'), ['task_id'],
                           unique=False)

    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('tasks_seen_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('users') as batch:
        batch.drop_column('tasks_seen_at')
    op.drop_table('task_checklist')
