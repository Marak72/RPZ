"""Одновременная работа фоновой выгрузки и страниц портала.

Боевой случай: во время выгрузки из SkyDNS сохранение задачи падало с
``sqlite3.OperationalError: database is locked``. SQLite пускает только
одного писателя, и длинная транзакция на тысячи доменов не оставляла
страницам портала ни одного окна для записи.

База здесь файловая, а не в памяти: у базы в памяти каждое соединение своё,
и блокировок между ними не бывает — то есть проверять было бы нечего.
"""
import threading

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text

from config import Config

from app import create_app
from app.core.extensions import db
from app.core.models import User
from app.services.skydns.models import ThreatDomain
from app.services.tasks.models import Task


@pytest.fixture
def app(tmp_path):
    class FileConfig(Config):
        TESTING = True
        WTF_CSRF_ENABLED = False
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'concurrency.db'}"
        SECRET_KEY = "test-secret"
        RPZ_FERNET_KEY = Fernet.generate_key().decode()

    application = create_app(FileConfig)
    with application.app_context():
        db.create_all()
        user = User(username="op", role="operator")
        user.set_password("pass")
        db.session.add(user)
        db.session.add(Task(number=1, title="Задача", reporter_id=None))
        db.session.commit()
        yield application


def test_sqlite_runs_in_wal_mode(app):
    """WAL — то, что вообще позволяет читать во время записи."""
    assert db.session.execute(text("PRAGMA journal_mode")).scalar() == "wal"


def test_busy_timeout_is_set(app):
    """Без ожидания вторая запись падает мгновенно, а не ждёт своей очереди."""
    assert db.session.execute(text("PRAGMA busy_timeout")).scalar() >= 15000


def test_page_can_save_while_a_background_job_writes(app):
    """Главная проверка: правка задачи проходит во время фоновой записи."""
    errors: list = []
    stop = threading.Event()

    def background_writer():
        """Фоновая выгрузка: много записей короткими транзакциями."""
        with app.app_context():
            try:
                for i in range(400):
                    db.session.add(ThreatDomain(
                        domain=f"evil{i}.ru", root_domain=f"evil{i}.ru",
                    ))
                    if i % 20 == 0:
                        db.session.commit()
                    if stop.is_set():
                        break
                db.session.commit()
            except Exception as exc:  # noqa: BLE001
                errors.append(("фон", exc))

    worker = threading.Thread(target=background_writer, daemon=True)
    worker.start()

    # Пока идёт выгрузка, страница портала сохраняет задачу — раз за разом.
    try:
        for i in range(30):
            task = Task.query.one()
            task.description = f"правка {i}"
            db.session.commit()
    except Exception as exc:  # noqa: BLE001
        errors.append(("страница", exc))
    finally:
        stop.set()
        worker.join(timeout=30)

    assert not errors, f"запись не прошла: {errors}"


def test_reading_is_not_blocked_by_a_write_in_progress(app):
    """Чтение страниц не должно ждать чужую запись — за это отвечает WAL."""
    started = threading.Event()
    release = threading.Event()
    errors: list = []

    def holder():
        with app.app_context():
            try:
                db.session.add(ThreatDomain(domain="x.ru", root_domain="x.ru"))
                db.session.flush()          # транзакция записи открыта
                started.set()
                release.wait(timeout=10)
                db.session.commit()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    assert started.wait(timeout=10)

    try:
        # Чужая незавершённая запись не должна мешать читать.
        assert Task.query.count() == 1
    finally:
        release.set()
        thread.join(timeout=10)

    assert not errors
