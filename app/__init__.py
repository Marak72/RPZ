"""Фабрика приложения Flask."""
import os

import click
from flask import Flask

from config import INSTANCE_DIR, Config
from .extensions import csrf, db, login_manager, migrate


def create_app(config_class: type = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(INSTANCE_DIR, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    # Регистрируем модели (нужно для миграций и user_loader).
    from . import models  # noqa: F401

    from .auth.routes import auth_bp
    from .main.routes import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    _register_cli(app)
    return app


def _register_cli(app: Flask) -> None:
    @app.cli.command("create-user")
    @click.argument("username")
    @click.option(
        "--role",
        default="operator",
        type=click.Choice(["operator", "manager"]),
        help="Роль пользователя.",
    )
    @click.password_option()
    def create_user(username: str, role: str, password: str) -> None:
        """Создать пользователя приложения."""
        from .models import User

        if User.query.filter_by(username=username).first():
            click.echo(f"Пользователь '{username}' уже существует.")
            return
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Пользователь '{username}' создан с ролью '{role}'.")

    @app.cli.command("init-db")
    def init_db() -> None:
        """Создать таблицы БД (для быстрого старта без миграций)."""
        db.create_all()
        click.echo("Таблицы базы данных созданы.")
