"""Задачи отдела: доска, комментарии и история изменений.

Revision ID: d51c8a4e7f26
Revises: c93a5d17be08
Create Date: 2026-08-10
"""
import sqlalchemy as sa
from alembic import op

revision = 'd51c8a4e7f26'
down_revision = 'c93a5d17be08'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'tasks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('number', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False,
                  server_default='backlog'),
        sa.Column('priority', sa.String(length=20), nullable=False,
                  server_default='normal'),
        sa.Column('service_id', sa.String(length=40), nullable=False,
                  server_default=''),
        sa.Column('assignee_id', sa.Integer(), nullable=True),
        sa.Column('reporter_id', sa.Integer(), nullable=True),
        sa.Column('due_date', sa.Date(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['assignee_id'], ['users.id']),
        sa.ForeignKeyConstraint(['reporter_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('tasks') as batch:
        batch.create_index(batch.f('ix_tasks_number'), ['number'], unique=True)
        batch.create_index(batch.f('ix_tasks_status'), ['status'], unique=False)
        batch.create_index(batch.f('ix_tasks_priority'), ['priority'], unique=False)
        batch.create_index(batch.f('ix_tasks_service_id'), ['service_id'],
                           unique=False)
        batch.create_index(batch.f('ix_tasks_assignee_id'), ['assignee_id'],
                           unique=False)
        batch.create_index(batch.f('ix_tasks_created_at'), ['created_at'],
                           unique=False)

    op.create_table(
        'task_comments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('task_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('body', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['task_id'], ['tasks.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('task_comments') as batch:
        batch.create_index(batch.f('ix_task_comments_task_id'), ['task_id'],
                           unique=False)
        batch.create_index(batch.f('ix_task_comments_created_at'),
                           ['created_at'], unique=False)

    op.create_table(
        'task_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('task_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('field', sa.String(length=40), nullable=False,
                  server_default=''),
        sa.Column('old_value', sa.String(length=300), nullable=True),
        sa.Column('new_value', sa.String(length=300), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['task_id'], ['tasks.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('task_events') as batch:
        batch.create_index(batch.f('ix_task_events_task_id'), ['task_id'],
                           unique=False)
        batch.create_index(batch.f('ix_task_events_created_at'), ['created_at'],
                           unique=False)

    # Новый сервис выдаём всем существующим учётным записям: иначе после
    # обновления задачи не увидит никто, кроме администраторов.
    connection = op.get_bind()
    for (user_id,) in connection.execute(sa.text("SELECT id FROM users")).fetchall():
        connection.execute(
            sa.text("INSERT INTO user_services (user_id, service_id) "
                    "VALUES (:user_id, 'tasks')"),
            {"user_id": user_id},
        )


def downgrade():
    connection = op.get_bind()
    connection.execute(sa.text("DELETE FROM user_services WHERE service_id = 'tasks'"))
    op.drop_table('task_events')
    op.drop_table('task_comments')
    op.drop_table('tasks')
