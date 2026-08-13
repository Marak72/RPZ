"""Фабрика приложения Flask.

Портал собирается из двух частей:

  * оболочка — ядро (``app/core``), вход, учётные записи, главная и фоновые
    задания. Она едина и одинакова для всех сервисов;
  * сервисы (``app/services/*``) — самостоятельные приложения, каждое целиком
    в своей папке. Здесь они только подключаются.
"""
import os

import click
from flask import Flask, render_template

from config import INSTANCE_DIR, Config
from .core.extensions import csrf, db, login_manager, migrate


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

    # Модели ядра: их должен видеть SQLAlchemy до создания таблиц и миграций.
    # Модели сервисов подтягиваются вместе с самими сервисами (ниже).
    from .core import models  # noqa: F401

    _configure_sqlite(app)

    from .admin.routes import admin_bp
    from .auth.routes import auth_bp
    from .hub.routes import hub_bp
    from .jobs.routes import jobs_bp
    from .services import SERVICE_BLUEPRINTS

    # Оболочка портала.
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(hub_bp)
    app.register_blueprint(jobs_bp)
    # Сервисы. Чтобы добавить новый сервис, достаточно завести папку в
    # app/services и внести его в реестр app/portal.py.
    for blueprint in SERVICE_BLUEPRINTS:
        app.register_blueprint(blueprint)

    _register_template_helpers(app)
    _register_portal_context(app)
    _register_error_handlers(app)
    _register_cli(app)
    return app


def _configure_sqlite(app: Flask) -> None:
    """Разрешить SQLite одновременную работу фоновых заданий и страниц.

    По умолчанию запись в SQLite блокирует базу целиком, и пока фоновый
    поток дописывает найденные хосты, любая страница портала падала бы с
    «database is locked». Журнал WAL разводит читателей и писателя, а
    busy_timeout заставляет второго писателя подождать, а не сдаться сразу.
    """
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    if not str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("sqlite"):
        return

    @event.listens_for(Engine, "connect")
    def _set_pragmas(dbapi_connection, _record):  # pragma: no cover - драйвер
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            mode = (cursor.fetchone() or [""])[0]
            # 30 секунд — это про ожидание чужой записи, а не про её длину:
            # свои транзакции портал держит короткими (см. WRITE_BATCH).
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA synchronous=NORMAL")
        except Exception:  # noqa: BLE001 — драйвер может быть не sqlite3
            return
        finally:
            cursor.close()

        # У базы в памяти журнал всегда "memory", и это правильно: там
        # одно соединение и делить нечего. Предупреждать не о чем.
        if str(mode).lower() not in ("wal", "memory"):
            # Без WAL любая запись блокирует читателей: портал будет падать
            # с «database is locked» каждый раз, когда идёт фоновая выгрузка.
            # Молчать об этом нельзя — причина неочевидна.
            app.logger.warning(
                "SQLite работает в режиме журнала %s вместо WAL. Обычно так "
                "бывает, если файл базы лежит на сетевой файловой системе. "
                "Страницы портала будут падать с «database is locked» во "
                "время фоновых выгрузок.", mode,
            )


def _register_template_helpers(app: Flask) -> None:
    """Помощники, нужные шаблонам всех сервисов."""
    from .core.web_utils import current_url

    app.jinja_env.globals["current_url"] = current_url
    app.jinja_env.globals["asset_version"] = _asset_version(app)


def _asset_version(app: Flask) -> str:
    """Метка версии для ссылок на css/js.

    Без неё браузер и обратный прокси продолжают отдавать старые файлы
    после обновления: страница уже новая, а скрипт к ней — прежний, и
    кнопки просто не работают. Метка меняется вместе с файлами, поэтому
    вопрос «почему после git pull ничего не изменилось» не возникает.
    """
    newest = 0.0
    for name in ("css/app.css", "js/app.js"):
        try:
            newest = max(newest, os.path.getmtime(
                os.path.join(app.static_folder, name)
            ))
        except OSError:
            continue
    return str(int(newest))


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
            message="Либо этот сервис не выдан вашей учётной записи, либо "
                    "действие доступно только операторам, а ваша роль "
                    "позволяет только просмотр.\n"
                    "Права выдаёт администратор портала.",
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
            message="Суммарный размер загружаемых файлов не должен превышать "
                    "32 МБ. Загрузите письма меньшими пачками.",
        ), 413

    @app.errorhandler(500)
    def server_error(error):
        app.logger.exception("Внутренняя ошибка: %s", error)
        db.session.rollback()

        # «database is locked» — не поломка, а гонка за запись: кто-то
        # держал базу дольше отведённого ожидания. Данные при этом целы,
        # и правильное действие — повторить, а не звать администратора.
        if "database is locked" in str(getattr(error, "original_exception", error)):
            return render_template(
                "error.html",
                code=500,
                title="База была занята",
                message="Изменения не сохранились: в этот момент шла фоновая "
                        "выгрузка, и база отказала в записи.\n"
                        "Вернитесь назад и повторите — данные не потеряны.",
            ), 500

        return render_template(
            "error.html",
            code=500,
            title="Внутренняя ошибка",
            message="Произошла непредвиденная ошибка. Подробности записаны "
                    "в журнал сервиса: journalctl -u soc-portal -n 100",
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
        from .core.models import User, UserService
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
        from .core.models import ROLE_ADMIN, User

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
        from .core.models import User

        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Пользователь '{username}' не найден.")
            return
        user.set_password(password)
        db.session.commit()
        click.echo(f"Пароль пользователя '{username}' обновлён.")

    @app.cli.command("jobs-reset")
    def jobs_reset() -> None:
        """Снять зависшие фоновые задания.

        После перезапуска службы поток-исполнитель не выживает, а запись о
        задании остаётся «выполняется» и блокирует запуск следующего. Эта
        команда закрывает такие записи сразу, не дожидаясь таймаута.
        """
        from .core.background import cancel_all

        count = cancel_all()
        click.echo(f"Снято незавершённых заданий: {count}.")

    @app.cli.command("init-db")
    def init_db() -> None:
        """Создать таблицы БД (для быстрого старта без миграций)."""
        db.create_all()
        click.echo("Таблицы базы данных созданы.")
