"""Состояние фоновых заданий для плашки прогресса.

Отдельный blueprint, а не часть сервиса: плашка живёт в общем каркасе
портала и должна работать на любой странице, включая чужие сервисы.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from ..extensions import db
from ..models import JOB_ACTIVE_STATUSES, BackgroundJob
from ..services.jobs import active_job  # noqa: F401  (переэкспорт для сервисов)
from ..services.jobs import cancel

jobs_bp = Blueprint("jobs", __name__, url_prefix="/jobs")

#: Сколько времени завершённое задание ещё показывается в плашке, если
#: оператор её не закрыл. Дольше держать незачем — итог уже в журнале.
KEEP_FINISHED = timedelta(minutes=30)


@jobs_bp.route("/status.json")
@login_required
def status():
    """Задания, о которых стоит рассказать текущему пользователю.

    Показываем все выполняющиеся задания (портал не запускает второе такое
    же, и второй оператор должен понимать, почему кнопка недоступна) и
    свои недавно завершённые, пока их не закрыли.
    """
    from ..services.jobs import _release_stale

    _release_stale()

    running = (
        BackgroundJob.query
        .filter(BackgroundJob.status.in_(JOB_ACTIVE_STATUSES))
        .order_by(BackgroundJob.created_at)
        .all()
    )
    finished = (
        BackgroundJob.query
        .filter(BackgroundJob.status.notin_(JOB_ACTIVE_STATUSES))
        .filter(BackgroundJob.user_id == current_user.id)
        .filter(BackgroundJob.dismissed_at.is_(None))
        .filter(BackgroundJob.finished_at >= datetime.utcnow() - KEEP_FINISHED)
        .order_by(BackgroundJob.finished_at)
        .all()
    )

    items = [job.as_dict() for job in running + finished]
    for item, job in zip(items, running + finished):
        item["mine"] = job.user_id == current_user.id
    return jsonify({"jobs": items})


@jobs_bp.route("/<int:job_id>/cancel", methods=["POST"])
@login_required
def cancel_job(job_id: int):
    """Снять идущее задание.

    Нужно, когда задание ушло не туда (не тот фильтр, не тот период) или
    осталось висеть после перезапуска службы. Без этого единственным
    способом запустить поиск заново было бы ждать десять минут, пока
    портал сам признает исполнителя пропавшим.
    """
    if not current_user.is_operator:
        return jsonify({"ok": False, "reason": "forbidden"}), 403
    job = db.session.get(BackgroundJob, job_id)
    if job is None:
        return jsonify({"ok": False}), 404
    if job.is_active:
        cancel(job)
    return jsonify({"ok": True})


@jobs_bp.route("/<int:job_id>/dismiss", methods=["POST"])
@login_required
def dismiss(job_id: int):
    """Убрать плашку завершённого задания."""
    job = db.session.get(BackgroundJob, job_id)
    if job is None:
        return jsonify({"ok": False}), 404
    if job.is_active:
        # Закрывать плашку идущей работы нечестно: оператор потеряет её из
        # виду и решит, что ничего не запускалось.
        return jsonify({"ok": False, "reason": "active"}), 409
    job.dismissed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True})
