"""Учётные записи сотрудников и доступ к сервисам портала.

Revision ID: c93a5d17be08
Revises: b8e21f40c7a5
Create Date: 2026-08-10
"""
import sqlalchemy as sa
from alembic import op

revision = 'c93a5d17be08'
down_revision = 'b8e21f40c7a5'
branch_labels = None
depends_on = None

# Сервисы, которые существуют на момент этой миграции. Держим списком здесь,
# а не импортом из приложения: миграция не должна меняться вслед за кодом.
SERVICE_IDS = ("fstec", "skydns")


def upgrade():
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('full_name', sa.String(length=200),
                                   nullable=False, server_default=''))
        batch.add_column(sa.Column('email', sa.String(length=200),
                                   nullable=False, server_default=''))
        batch.add_column(sa.Column('position', sa.String(length=200),
                                   nullable=False, server_default=''))
        batch.add_column(sa.Column('is_enabled', sa.Boolean(), nullable=False,
                                   server_default=sa.true()))
        batch.add_column(sa.Column('last_login_at', sa.DateTime(), nullable=True))

    op.create_table(
        'user_services',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('service_id', sa.String(length=40), nullable=False),
        sa.Column('granted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'service_id', name='uq_user_service'),
    )
    with op.batch_alter_table('user_services') as batch:
        batch.create_index(batch.f('ix_user_services_user_id'), ['user_id'],
                           unique=False)
        batch.create_index(batch.f('ix_user_services_service_id'),
                           ['service_id'], unique=False)

    # Существующим учётным записям выдаём все сервисы: до этой миграции доступ
    # не разграничивался, и обновление не должно отнимать права.
    connection = op.get_bind()
    users = connection.execute(sa.text("SELECT id, role FROM users")).fetchall()
    for user_id, _role in users:
        for service_id in SERVICE_IDS:
            connection.execute(
                sa.text(
                    "INSERT INTO user_services (user_id, service_id) "
                    "VALUES (:user_id, :service_id)"
                ),
                {"user_id": user_id, "service_id": service_id},
            )

    # Первый оператор становится администратором — иначе после обновления
    # некому будет заводить учётные записи.
    first_operator = connection.execute(
        sa.text("SELECT id FROM users WHERE role = 'operator' ORDER BY id LIMIT 1")
    ).fetchone()
    if first_operator:
        connection.execute(
            sa.text("UPDATE users SET role = 'admin' WHERE id = :id"),
            {"id": first_operator[0]},
        )


def downgrade():
    connection = op.get_bind()
    connection.execute(sa.text("UPDATE users SET role = 'operator' "
                               "WHERE role = 'admin'"))
    op.drop_table('user_services')
    with op.batch_alter_table('users') as batch:
        batch.drop_column('last_login_at')
        batch.drop_column('is_enabled')
        batch.drop_column('position')
        batch.drop_column('email')
        batch.drop_column('full_name')
