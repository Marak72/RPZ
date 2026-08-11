"""Фоновые задания портала.

Зачем. Поиск конечных хостов в SIEM делает отдельный запрос на каждый домен,
выгрузка из SkyDNS ждёт готовности отчёта. И то и другое занимает минуты.
Пока это выполнялось прямо в обработчике запроса, браузер висел на кнопке,
а Apache мог оборвать соединение по своему таймауту — оператор при этом не
знал, доделалась работа или нет.

Как устроено. Обработчик заводит запись ``BackgroundJob``, отдаёт страницу
сразу и запускает поток-исполнитель. Поток пишет прогресс в ту же запись,
браузер спрашивает о нём отдельным лёгким запросом и рисует плашку.

Почему поток, а не очередь задач. Приложение ставится в изолированной сети,
где нет ни брокера, ни возможности доставить пакет с PyPI. Работа здесь
целиком ожидание сети, поэтому GIL не мешает: поток спит на сокете, а
рабочий процесс в это время обслуживает другие запросы.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta

from ..extensions import db
from ..models import (
    JOB_ACTIVE_STATUSES,
    JOB_FAILED,
    JOB_QUEUED,
    JOB_RUNNING,
    JOB_SUCCESS,
    BackgroundJob,
)

#: Если поток не подавал признаков жизни дольше этого срока, считаем, что
#: рабочий процесс умер вместе с заданием: иначе оно навсегда осталось бы
#: «выполняется» и блокировало запуск следующего.
STALE_AFTER = timedelta(minutes=10)


class JobCancelled(Exception):
    """Задание сняли — исполнителю пора прекратить работу."""


class JobError(Exception):
    """Ожидаемая ошибка исполнителя: текст показывается оператору как есть.

    Отличается от прочих исключений только подачей: «SIEM отклонил вход
    (401)» — это внятная причина, и приписка «непредвиденная ошибка» к ней
    только сбивает с толку.
    """


class JobHandle:
    """То, что видит исполнитель: способ отчитаться о ходе работы.

    Каждое обновление — отдельная короткая транзакция. Держать её открытой
    на всё задание нельзя: страницы портала не смогли бы читать базу.
    """

    def __init__(self, job_id: int) -> None:
        self.job_id = job_id

    @property
    def job(self) -> BackgroundJob:
        return db.session.get(BackgroundJob, self.job_id)

    def check(self) -> None:
        """Прерваться, если задание сняли.

        Отдельно от :meth:`progress`, потому что вызывать её имеет смысл
        куда чаще, чем отчитываться: между двумя отчётами исполнитель может
        просидеть на медленном запросе не одну минуту, и всё это время
        нажатая оператором отмена выглядела бы как «не работает».
        """
        job = self.job
        if job is None:
            raise JobCancelled("Задание удалено.")
        if not job.is_active:
            raise JobCancelled("Задание снято.")

    def progress(self, processed: int | None = None, detail: str = "",
                 failed: int | None = None, found: int | None = None,
                 error: str = "") -> None:
        job = self.job
        if job is None:
            raise JobCancelled("Задание удалено.")
        if not job.is_active:
            # Оператор снял задание (или его закрыли как зависшее). Работать
            # дальше незачем: запись уже завершена, и всё, что мы допишем,
            # только запутает — поэтому исполнитель останавливается здесь.
            raise JobCancelled("Задание снято.")
        if processed is not None:
            job.processed = processed
        if failed is not None:
            job.failed = failed
        if found is not None:
            job.result_count = found
        if detail:
            job.detail = detail[:300]
        if error and not job.message:
            # Первая ошибка показывается в плашке сразу, не дожидаясь конца
            # задания: иначе оператор час смотрит на растущий счётчик ошибок
            # и не знает, что именно отвечает SIEM.
            job.message = error[:2000]
        job.heartbeat_at = datetime.utcnow()
        db.session.commit()

    def set_total(self, total: int) -> None:
        job = self.job
        if job is not None:
            job.total = total
            db.session.commit()


def active_job(kind: str) -> BackgroundJob | None:
    """Незавершённое задание этого вида, если оно ещё живо.

    Задания одного вида не запускаются параллельно: два поиска в SIEM
    одновременно только поделят между собой и без того небыстрый SIEM.
    """
    _release_stale()
    return (
        BackgroundJob.query
        .filter(BackgroundJob.kind == kind,
                BackgroundJob.status.in_(JOB_ACTIVE_STATUSES))
        .order_by(BackgroundJob.created_at.desc())
        .first()
    )


def _release_stale() -> None:
    """Закрыть задания, чей исполнитель не отзывается."""
    deadline = datetime.utcnow() - STALE_AFTER
    stale = (
        BackgroundJob.query
        .filter(BackgroundJob.status.in_(JOB_ACTIVE_STATUSES))
        .filter(db.func.coalesce(BackgroundJob.heartbeat_at,
                                 BackgroundJob.created_at) < deadline)
        .all()
    )
    if not stale:
        return
    for job in stale:
        job.status = JOB_FAILED
        job.finished_at = datetime.utcnow()
        job.message = (
            "Задание прервано: рабочий процесс перестал отвечать "
            "(перезапуск сервиса или обрыв связи). Запустите его заново."
        )
    db.session.commit()


def _run_inline(app) -> bool:
    """Выполнять задание прямо в вызывающем потоке, без фона.

    Так работают тесты: у отдельного потока своя сессия к базе, а тестовая
    база живёт в памяти процесса — поток до неё просто не достучится, да и
    проверять прогресс во времени в тесте нечем.
    """
    value = app.config.get("JOBS_RUN_INLINE")
    if value is None:
        return bool(app.config.get("TESTING"))
    return bool(value)


def cancel(job: BackgroundJob, reason: str = "Снято оператором.") -> None:
    """Снять задание.

    Поток остановится сам: он сверяется с состоянием записи на каждом шаге.
    Ждать его не нужно — запись уже закрыта, и новое задание можно
    запускать сразу.
    """
    job.status = JOB_FAILED
    job.finished_at = datetime.utcnow()
    job.heartbeat_at = job.finished_at
    job.detail = ""
    job.message = (job.message + " " if job.message else "") + reason
    db.session.commit()


def cancel_all(kind: str = "") -> int:
    """Снять все незавершённые задания (при необходимости — только вида)."""
    query = BackgroundJob.query.filter(
        BackgroundJob.status.in_(JOB_ACTIVE_STATUSES)
    )
    if kind:
        query = query.filter(BackgroundJob.kind == kind)
    rows = query.all()
    for job in rows:
        cancel(job, "Снято при сбросе заданий.")
    return len(rows)


def start(app, *, kind: str, title: str, worker, service_id: str = "",
          total: int = 0, user_id: int | None = None,
          target_url: str = "") -> BackgroundJob:
    """Завести задание и запустить исполнителя в отдельном потоке.

    ``worker`` получает единственный аргумент — :class:`JobHandle` — и должен
    вернуть строку с итогом работы. Исключение внутри исполнителя переводит
    задание в состояние ошибки, текст попадает оператору в плашку.
    """
    job = BackgroundJob(
        kind=kind, title=title, service_id=service_id, total=total,
        user_id=user_id, target_url=target_url, status=JOB_QUEUED,
        heartbeat_at=datetime.utcnow(),
    )
    db.session.add(job)
    db.session.commit()

    if _run_inline(app):
        _execute_inline(job.id, worker)
        return db.session.get(BackgroundJob, job.id)

    thread = threading.Thread(
        target=_run, args=(app, job.id, worker), name=f"job-{kind}-{job.id}",
        daemon=True,
    )
    thread.start()
    return job


def _run(app, job_id: int, worker) -> None:
    """Тело потока-исполнителя: своя сессия БД, свой контекст приложения."""
    with app.app_context():
        handle = JobHandle(job_id)
        job = handle.job
        if job is None:
            return
        job.status = JOB_RUNNING
        job.started_at = datetime.utcnow()
        job.heartbeat_at = job.started_at
        db.session.commit()

        try:
            summary = worker(handle)
        except JobCancelled:
            db.session.rollback()
            return
        except Exception as exc:  # noqa: BLE001 — исполнитель ходит в сеть
            if not isinstance(exc, JobError):
                app.logger.exception("Фоновое задание %s упало", job_id)
            _finish_failed(handle, exc)
            return

        _finish_ok(handle, summary)


def _execute_inline(job_id: int, worker) -> None:
    handle = JobHandle(job_id)
    job = handle.job
    job.status = JOB_RUNNING
    job.started_at = datetime.utcnow()
    db.session.commit()
    try:
        summary = worker(handle)
    except Exception as exc:  # noqa: BLE001
        _finish_failed(handle, exc)
        return
    _finish_ok(handle, summary)


def _finish_ok(handle: JobHandle, summary: str) -> None:
    job = handle.job
    if job is None or not job.is_active:
        # Задание успели снять — не воскрешаем его задним числом.
        return
    job.status = JOB_SUCCESS
    job.finished_at = datetime.utcnow()
    job.heartbeat_at = job.finished_at
    job.detail = ""
    job.message = summary or "Готово."
    db.session.commit()


def _finish_failed(handle: JobHandle, exc: Exception) -> None:
    # Незавершённую работу исполнителя откатываем: наполовину записанные
    # результаты хуже, чем честно показанная ошибка.
    db.session.rollback()
    job = handle.job
    if job is None or not job.is_active:
        return
    job.status = JOB_FAILED
    job.finished_at = datetime.utcnow()
    job.heartbeat_at = job.finished_at
    job.detail = ""
    job.message = (
        str(exc) if isinstance(exc, JobError) else f"Непредвиденная ошибка: {exc}"
    )
    db.session.commit()
