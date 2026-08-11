"""Фоновые задания: запуск, прогресс, плашка и снятие зависших.

Поток здесь не запускается: в тестовой конфигурации задания выполняются
прямо в вызывающем потоке (см. ``JOBS_RUN_INLINE``), иначе поток со своей
сессией не достучался бы до базы в памяти процесса.
"""
from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from config import Config

from app import create_app
from app.extensions import db
from app.models import (
    JOB_FAILED,
    JOB_KIND_SIEM,
    JOB_QUEUED,
    JOB_RUNNING,
    JOB_SUCCESS,
    BackgroundJob,
    User,
    UserService,
)
from app.portal import SERVICES
from app.services import jobs


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    RPZ_FERNET_KEY = Fernet.generate_key().decode()


@pytest.fixture
def app():
    application = create_app(TestConfig)
    with application.app_context():
        db.create_all()
        user = User(username="op", role="operator")
        user.set_password("pass")
        db.session.add(user)
        db.session.flush()
        for service in SERVICES:
            db.session.add(UserService(user_id=user.id, service_id=service.id))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    test_client = app.test_client()
    test_client.post("/login", data={"username": "op", "password": "pass"})
    return test_client


def _user_id() -> int:
    return User.query.one().id


# --- запуск и завершение --------------------------------------------------

def test_job_runs_and_records_summary(app):
    def work(handle):
        handle.progress(processed=1, detail="первый", found=3)
        handle.progress(processed=2, found=5)
        return "Готово: 5."

    job = jobs.start(app, kind=JOB_KIND_SIEM, title="Тест", worker=work,
                     total=2, user_id=_user_id())
    assert job.status == JOB_SUCCESS
    assert job.processed == 2
    assert job.result_count == 5
    assert job.message == "Готово: 5."
    assert job.percent == 100
    assert job.finished_at is not None


def test_job_failure_is_recorded_not_raised(app):
    def work(_handle):
        raise RuntimeError("SIEM недоступен")

    job = jobs.start(app, kind=JOB_KIND_SIEM, title="Тест", worker=work,
                     user_id=_user_id())
    assert job.status == JOB_FAILED
    assert "SIEM недоступен" in job.message


def test_progress_is_visible_while_the_job_runs(app):
    """Плашка обновляется по ходу работы, а не только в конце."""
    seen = {}

    def work(handle):
        handle.progress(processed=1, detail="ищу a.ru")
        # Снимок состояния прямо из базы: именно его отдаёт status.json.
        row = db.session.get(BackgroundJob, handle.job_id)
        seen["status"] = row.status
        seen["processed"] = row.processed
        seen["detail"] = row.detail
        return "ок"

    jobs.start(app, kind=JOB_KIND_SIEM, title="Тест", worker=work, total=4,
               user_id=_user_id())
    assert seen == {"status": JOB_RUNNING, "processed": 1, "detail": "ищу a.ru"}


def test_percent_survives_zero_total(app):
    job = BackgroundJob(kind=JOB_KIND_SIEM, total=0, processed=3)
    assert job.percent == 0


# --- одно задание вида за раз ---------------------------------------------

def test_active_job_of_the_same_kind_is_found(app):
    job = BackgroundJob(kind=JOB_KIND_SIEM, status=JOB_RUNNING,
                        heartbeat_at=datetime.utcnow())
    db.session.add(job)
    db.session.commit()
    assert jobs.active_job(JOB_KIND_SIEM) is not None


def test_finished_job_does_not_block_the_next_one(app):
    db.session.add(BackgroundJob(kind=JOB_KIND_SIEM, status=JOB_SUCCESS))
    db.session.commit()
    assert jobs.active_job(JOB_KIND_SIEM) is None


def test_stale_job_is_released(app):
    """Если рабочий процесс умер, задание не должно висеть вечно.

    Иначе кнопка поиска осталась бы заблокированной навсегда: портал
    считал бы, что работа всё ещё идёт.
    """
    job = BackgroundJob(
        kind=JOB_KIND_SIEM, status=JOB_RUNNING,
        heartbeat_at=datetime.utcnow() - jobs.STALE_AFTER - timedelta(minutes=1),
    )
    db.session.add(job)
    db.session.commit()

    assert jobs.active_job(JOB_KIND_SIEM) is None
    assert db.session.get(BackgroundJob, job.id).status == JOB_FAILED


def test_job_without_heartbeat_is_judged_by_creation_time(app):
    job = BackgroundJob(
        kind=JOB_KIND_SIEM, status=JOB_QUEUED, heartbeat_at=None,
        created_at=datetime.utcnow() - jobs.STALE_AFTER - timedelta(minutes=1),
    )
    db.session.add(job)
    db.session.commit()
    assert jobs.active_job(JOB_KIND_SIEM) is None


# --- состояние для плашки -------------------------------------------------

def test_status_endpoint_reports_running_jobs(client):
    db.session.add(BackgroundJob(
        kind=JOB_KIND_SIEM, title="Поиск", status=JOB_RUNNING, total=10,
        processed=4, result_count=7, detail="ищу evil.ru",
        heartbeat_at=datetime.utcnow(), user_id=_user_id(),
    ))
    db.session.commit()

    payload = client.get("/jobs/status.json").get_json()
    assert len(payload["jobs"]) == 1
    item = payload["jobs"][0]
    assert item["active"] is True
    assert item["percent"] == 40
    assert item["detail"] == "ищу evil.ru"
    assert item["found"] == 7


def test_status_endpoint_shows_own_finished_job(client):
    db.session.add(BackgroundJob(
        kind=JOB_KIND_SIEM, title="Поиск", status=JOB_SUCCESS,
        message="Найдено хостов: 3.", finished_at=datetime.utcnow(),
        user_id=_user_id(),
    ))
    db.session.commit()

    item = client.get("/jobs/status.json").get_json()["jobs"][0]
    assert item["active"] is False
    assert item["message"] == "Найдено хостов: 3."


def test_dismissed_job_disappears_from_the_tray(client):
    job = BackgroundJob(
        kind=JOB_KIND_SIEM, title="Поиск", status=JOB_SUCCESS,
        finished_at=datetime.utcnow(), user_id=_user_id(),
    )
    db.session.add(job)
    db.session.commit()

    assert client.post(f"/jobs/{job.id}/dismiss").get_json()["ok"] is True
    assert client.get("/jobs/status.json").get_json()["jobs"] == []


def test_running_job_cannot_be_dismissed(client):
    """Спрятать идущую работу — значит потерять её из виду."""
    job = BackgroundJob(
        kind=JOB_KIND_SIEM, title="Поиск", status=JOB_RUNNING,
        heartbeat_at=datetime.utcnow(), user_id=_user_id(),
    )
    db.session.add(job)
    db.session.commit()

    assert client.post(f"/jobs/{job.id}/dismiss").status_code == 409


def test_old_finished_job_is_not_shown_forever(client):
    db.session.add(BackgroundJob(
        kind=JOB_KIND_SIEM, title="Старое", status=JOB_SUCCESS,
        finished_at=datetime.utcnow() - timedelta(hours=3), user_id=_user_id(),
    ))
    db.session.commit()
    assert client.get("/jobs/status.json").get_json()["jobs"] == []


def test_status_requires_login(app):
    anonymous = app.test_client()
    assert anonymous.get("/jobs/status.json").status_code in (302, 401)


def test_expected_error_is_shown_without_the_scary_prefix(app):
    """«SIEM отклонил вход (401)» — внятная причина, приписка ей не нужна."""
    def work(_handle):
        raise jobs.JobError("SIEM отклонил вход (401).")

    job = jobs.start(app, kind=JOB_KIND_SIEM, title="Тест", worker=work,
                     user_id=_user_id())
    assert job.status == JOB_FAILED
    assert job.message == "SIEM отклонил вход (401)."
