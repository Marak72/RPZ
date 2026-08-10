"""Фабрика приложения Flask."""
import os

import click
from flask import Flask, render_template

from config import INSTANCE_DIR, Config
from .extensions import csrf, db, login_manager, migrate


def create_app(config_class: type = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(INSTANCE_DIR, exist_ok=True)

    # За обратным прокси (nginx) на подпути: доверяем X-Forwarded-* заголовкам,
    # чтобы url_for и редиректы учитывали префикс (X-Forwarded-Prefix) и https.
    if app.config.get("BEHIND_PROXY"):
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    # Регистрируем модели (нужно для миграций и user_loader).
    from . import models  # noqa: F401

    from .admin.routes import admin_bp
    from .auth.routes import auth_bp
    from .hub.routes import hub_bp
    from .main.routes import main_bp
    from .skydns.routes import skydns_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(hub_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(skydns_bp)

    _register_portal_context(app)
    _register_error_handlers(app)
    _register_cli(app)
    return app


def _register_portal_context(app: Flask) -> None:
    """Отдать шаблонам список сервисов портала и активную вкладку."""
    from flask import request

    from .portal import HUB, SERVICES, service_by_blueprint

    @app.context_processor
    def inject_services():
        from flask_login import current_user

        # В переключателе показываем только то, что выдано пользователю.
        if current_user.is_authenticated:
            allowed = [s for s in SERVICES if current_user.can_use(s.id)]
        else:
            allowed = []
        return {
            "hub": HUB,
            "services": allowed,
            "all_services": SERVICES,
            "active_service": service_by_blueprint(request.blueprint),
        }


def _register_error_handlers(app: Flask) -> None:
    """Показывать понятные страницы вместо трассировок."""

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template(
            "error.html",
            code=403,
            title="Доступ запрещён",
            message="Этот раздел доступен только операторам. "
                    "Ваша роль позволяет только просмотр.",
        ), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html",
            code=404,
            title="Страница не найдена",
            message="Запрошенная страница или запись не существует.",
        ), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template(
            "error.html",
            code=413,
            title="Файл слишком большой",
            message="Размер загружаемого письма не должен превышать 10 МБ.",
        ), 413

    @app.errorhandler(500)
    def server_error(error):
        app.logger.exception("Внутренняя ошибка: %s", error)
        db.session.rollback()
        return render_template(
            "error.html",
            code=500,
            title="Внутренняя ошибка",
            message="Произошла непредвиденная ошибка. "
                    "Подробности записаны в журнал сервиса (journalctl -u fstec).",
        ), 500


def _register_cli(app: Flask) -> None:
    @app.cli.command("create-user")
    @click.argument("username")
    @click.option(
        "--role",
        default="operator",
        type=click.Choice(["admin", "operator", "manager"]),
        help="Роль пользователя.",
    )
    @click.option("--full-name", default="", help="ФИО сотрудника.")
    @click.password_option()
    def create_user(username: str, role: str, full_name: str,
                    password: str) -> None:
        """Создать пользователя портала (со всеми сервисами)."""
        from .models import User, UserService
        from .portal import SERVICES

        if User.query.filter_by(username=username).first():
            click.echo(f"Пользователь '{username}' уже существует.")
            return
        user = User(username=username, role=role, full_name=full_name)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        # Из командной строки заводят первую учётную запись — ей нужны все
        # сервисы, иначе портал окажется пустым. Сузить можно в веб-интерфейсе.
        for service in SERVICES:
            db.session.add(UserService(user_id=user.id, service_id=service.id))
        db.session.commit()
        click.echo(f"Пользователь '{username}' создан с ролью '{role}'.")

    @app.cli.command("grant-admin")
    @click.argument("username")
    def grant_admin(username: str) -> None:
        """Выдать существующему пользователю роль администратора."""
        from .models import ROLE_ADMIN, User

        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Пользователь '{username}' не найден.")
            return
        user.role = ROLE_ADMIN
        db.session.commit()
        click.echo(f"Пользователь '{username}' теперь администратор.")

    @app.cli.command("set-password")
    @click.argument("username")
    @click.password_option()
    def set_password(username: str, password: str) -> None:
        """Сменить пароль существующего пользователя."""
        from .models import User

        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Пользователь '{username}' не найден.")
            return
        user.set_password(password)
        db.session.commit()
        click.echo(f"Пароль пользователя '{username}' обновлён.")

    @app.cli.command("init-db")
    def init_db() -> None:
        """Создать таблицы БД (для быстрого старта без миграций)."""
        db.create_all()
        click.echo("Таблицы базы данных созданы.")
