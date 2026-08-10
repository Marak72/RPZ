"""Сервис «Задачи отдела».

Небольшой трекер под работу отдела: доска по статусам, карточка задачи с
комментариями и историей изменений. Номер задачи (``SOC-12``) выдаётся при
создании и не меняется — на него ссылаются в переписке.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func, or_

from ..extensions import db
from ..models import (
    TASK_DONE,
    TASK_PROGRESS,
    TASK_PRIORITIES,
    TASK_BACKLOG,
    TASK_PRIORITY_ORDER,
    TASK_TODO,
    TASK_STATUSES,
    Task,
    TaskChecklistItem,
    TaskComment,
    TaskEvent,
    User,
)
from ..portal import SERVICES
from ..settings_store import KEY_TASK_COUNTER, get_int, set_setting
from ..web_utils import (
    LazyCounts,
    csv_response,
    fmt_dt,
    operator_required,
    service_guard,
)
from .forms import ChecklistForm, CommentForm, QuickTaskForm, TaskForm

tasks_bp = Blueprint("tasks", __name__, url_prefix="/tasks")
tasks_bp.before_request(service_guard("tasks"))

PER_PAGE = 100

# Что показываем в истории вместо технических имён полей.
FIELD_TITLES = {
    "status": "статус",
    "priority": "приоритет",
    "assignee": "исполнитель",
    "title": "название",
    "description": "описание",
    "due_date": "срок",
    "service": "сервис",
    "created": "создана",
    "checklist": "пункт выполнения",
}


TASK_COUNTS_EMPTY = {"open": 0, "mine": 0, "overdue": 0, "updates": 0}


def _task_counts() -> dict:
    open_q = Task.query.filter(Task.status != TASK_DONE)
    updates = (
        TaskEvent.query.join(Task, TaskEvent.task_id == Task.id)
        .filter(TaskEvent.user_id != current_user.id)
        .filter(or_(Task.assignee_id == current_user.id,
                    Task.reporter_id == current_user.id))
    )
    if current_user.tasks_seen_at:
        updates = updates.filter(TaskEvent.created_at > current_user.tasks_seen_at)
    return {
        "open": open_q.count(),
        "mine": open_q.filter(Task.assignee_id == current_user.id).count(),
        "overdue": open_q.filter(Task.due_date.isnot(None),
                                 Task.due_date < date.today()).count(),
        "updates": updates.count(),
    }


@tasks_bp.app_context_processor
def inject_task_counts():
    """Счётчики для боковой навигации — считаются, только если нужны."""
    if not current_user.is_authenticated:
        return {"task_counts": LazyCounts(dict, TASK_COUNTS_EMPTY)}
    return {"task_counts": LazyCounts(_task_counts, TASK_COUNTS_EMPTY)}


def _next_number() -> int:
    """Выдать следующий номер задачи.

    Счётчик хранится отдельно от таблицы и только растёт: если считать по
    ``max(number)``, то после удаления последней задачи её номер выдался бы
    заново — а на него уже могли сослаться в переписке.
    """
    used = max(
        get_int(KEY_TASK_COUNTER, 0),
        db.session.query(func.max(Task.number)).scalar() or 0,
    )
    number = used + 1
    set_setting(KEY_TASK_COUNTER, str(number))
    return number


def _people() -> list:
    return User.query.filter_by(is_enabled=True).order_by(User.username).all()


def _prepare(form: TaskForm) -> None:
    """Заполнить списки выбора актуальными значениями."""
    form.assignee_id.choices = [(0, "— не назначен —")] + [
        (u.id, u.display_name) for u in _people()
    ]
    form.service_id.choices = [("", "— без привязки —")] + [
        (svc.id, svc.title) for svc in SERVICES if svc.id != "tasks"
    ]


def _log(task: Task, field: str, old, new) -> None:
    """Записать изменение в историю, если оно действительно есть."""
    old_text = "" if old in (None, "") else str(old)
    new_text = "" if new in (None, "") else str(new)
    if old_text == new_text:
        return
    db.session.add(TaskEvent(
        task_id=task.id, user_id=current_user.id, field=field,
        old_value=old_text[:300], new_value=new_text[:300],
    ))


def _assignee_name(user_id) -> str:
    if not user_id:
        return ""
    user = db.session.get(User, user_id)
    return user.display_name if user else ""


# --- Доска ----------------------------------------------------------------

@tasks_bp.route("/")
@login_required
def board():
    """Доска: колонка на каждый статус."""
    query = _filtered_query()
    tasks = query.all()
    # Сортировка внутри колонки: сначала приоритет, потом срок.
    tasks.sort(key=lambda t: (
        TASK_PRIORITY_ORDER.get(t.priority, 9),
        t.due_date or date.max,
        -t.number,
    ))

    columns = [
        # Ключ намеренно не "items": в Jinja он разрешается в метод словаря.
        {"code": code, "title": title,
         "cards": [t for t in tasks if t.status == code]}
        for code, title in TASK_STATUSES
    ]
    return render_template(
        "tasks/board.html",
        columns=columns,
        statuses=TASK_STATUSES,
        people=_people(),
        # Не "services": так называется список сервисов портала в общей
        # вёрстке, и переменная шаблона его перекрыла бы — из переключателя
        # пропала бы вкладка самого сервиса задач.
        filter_services=[s for s in SERVICES if s.id != "tasks"],
        filters=_current_filters(),
        total=len(tasks),
    )


def _current_filters() -> dict:
    return {
        "q": (request.args.get("q") or "").strip(),
        "assignee": request.args.get("assignee", ""),
        "priority": request.args.get("priority", ""),
        "service": request.args.get("service", ""),
        "mine": request.args.get("mine", ""),
        "overdue": request.args.get("overdue", ""),
        "closed": request.args.get("closed", ""),
    }


def _filtered_query():
    filters = _current_filters()
    query = Task.query

    if filters["q"]:
        pattern = f"%{filters['q']}%"
        query = query.filter(or_(Task.title.ilike(pattern),
                                 Task.description.ilike(pattern)))
    if filters["mine"]:
        query = query.filter(Task.assignee_id == current_user.id)
    elif filters["assignee"] == "none":
        query = query.filter(Task.assignee_id.is_(None))
    elif filters["assignee"].isdigit():
        query = query.filter(Task.assignee_id == int(filters["assignee"]))

    if filters["priority"]:
        query = query.filter(Task.priority == filters["priority"])
    if filters["service"]:
        query = query.filter(Task.service_id == filters["service"])
    if filters["overdue"]:
        query = query.filter(Task.due_date.isnot(None),
                             Task.due_date < date.today(),
                             Task.status != TASK_DONE)
    return query


# --- Список ---------------------------------------------------------------

@tasks_bp.route("/list")
@login_required
def task_list():
    page = request.args.get("page", 1, type=int)
    status = (request.args.get("status") or "").strip()
    query = _filtered_query()
    if status:
        query = query.filter(Task.status == status)
    elif not request.args.get("closed"):
        query = query.filter(Task.status != TASK_DONE)

    pagination = (
        query.order_by(Task.status, Task.number.desc())
        .paginate(page=page, per_page=PER_PAGE, error_out=False)
    )
    return render_template(
        "tasks/list.html",
        items=pagination.items,
        pagination=pagination,
        statuses=TASK_STATUSES,
        priorities=TASK_PRIORITIES,
        people=_people(),
        # Не "services": так называется список сервисов портала в общей
        # вёрстке, и переменная шаблона его перекрыла бы — из переключателя
        # пропала бы вкладка самого сервиса задач.
        filter_services=[s for s in SERVICES if s.id != "tasks"],
        filters=_current_filters(),
        status=status,
    )


@tasks_bp.route("/tasks.csv")
@login_required
def tasks_csv():
    rows = _filtered_query().order_by(Task.number).all()
    return csv_response(
        "soc-tasks",
        ["Номер", "Название", "Статус", "Приоритет", "Исполнитель",
         "Сервис", "Срок", "Создана", "Закрыта"],
        [
            [t.key, t.title, t.status_title, t.priority_title,
             t.assignee.display_name if t.assignee else "",
             t.service_id, t.due_date.strftime("%d.%m.%Y") if t.due_date else "",
             fmt_dt(t.created_at), fmt_dt(t.closed_at)]
            for t in rows
        ],
    )


# --- Карточка -------------------------------------------------------------

@tasks_bp.route("/<int:task_id>", methods=["GET", "POST"])
@login_required
def task_view(task_id: int):
    task = db.get_or_404(Task, task_id)
    comment_form = CommentForm()
    checklist_form = ChecklistForm()

    if comment_form.submit_comment.data and comment_form.validate_on_submit():
        if not current_user.is_operator:
            flash("Комментировать могут только операторы.", "danger")
            return redirect(url_for("tasks.task_view", task_id=task.id))
        db.session.add(TaskComment(
            task_id=task.id, user_id=current_user.id,
            body=comment_form.body.data.strip(),
        ))
        db.session.commit()
        flash("Комментарий добавлен.", "success")
        return redirect(url_for("tasks.task_view", task_id=task.id))

    return render_template(
        "tasks/task.html",
        task=task,
        comment_form=comment_form,
        statuses=TASK_STATUSES,
        checklist_form=checklist_form,
        checklist=task.checklist.all(),
        comments=task.comments.order_by(TaskComment.created_at).all(),
        events=task.events.order_by(TaskEvent.created_at.desc()).all(),
        field_titles=FIELD_TITLES,
    )


@tasks_bp.route("/new", methods=["GET", "POST"])
@operator_required
def task_new():
    form = TaskForm()
    _prepare(form)
    if request.method == "GET":
        form.service_id.data = request.args.get("service", "")

    if form.validate_on_submit():
        task = Task(
            number=_next_number(),
            title=form.title.data.strip(),
            description=form.description.data or "",
            status=form.status.data,
            priority=form.priority.data,
            service_id=form.service_id.data or "",
            assignee_id=form.assignee_id.data or None,
            reporter_id=current_user.id,
            due_date=form.due_date.data,
        )
        db.session.add(task)
        db.session.flush()
        _log(task, "created", "", task.key)
        db.session.commit()
        flash(f"Задача {task.key} создана.", "success")
        return redirect(url_for("tasks.task_view", task_id=task.id))

    return render_template("tasks/task_form.html", form=form, task=None)


@tasks_bp.route("/<int:task_id>/edit", methods=["GET", "POST"])
@operator_required
def task_edit(task_id: int):
    task = db.get_or_404(Task, task_id)
    form = TaskForm(obj=task)
    _prepare(form)
    if request.method == "GET":
        form.assignee_id.data = task.assignee_id or 0
        form.service_id.data = task.service_id or ""

    if form.validate_on_submit():
        _log(task, "title", task.title, form.title.data.strip())
        _log(task, "description", task.description, form.description.data or "")
        _log(task, "status", task.status_title,
             dict(TASK_STATUSES).get(form.status.data, form.status.data))
        _log(task, "priority", task.priority_title,
             dict(TASK_PRIORITIES).get(form.priority.data, form.priority.data))
        _log(task, "assignee", _assignee_name(task.assignee_id),
             _assignee_name(form.assignee_id.data or None))
        _log(task, "service", task.service_id, form.service_id.data or "")
        _log(task, "due_date", task.due_date, form.due_date.data)

        was_open = task.is_open
        task.title = form.title.data.strip()
        task.description = form.description.data or ""
        task.status = form.status.data
        task.priority = form.priority.data
        task.service_id = form.service_id.data or ""
        task.assignee_id = form.assignee_id.data or None
        task.due_date = form.due_date.data
        _touch_closed(task, was_open)

        db.session.commit()
        flash(f"Задача {task.key} сохранена.", "success")
        return redirect(url_for("tasks.task_view", task_id=task.id))

    return render_template("tasks/task_form.html", form=form, task=task)


def _touch_closed(task: Task, was_open: bool) -> None:
    """Проставить или снять отметку о закрытии."""
    if was_open and not task.is_open:
        task.closed_at = datetime.utcnow()
    elif not was_open and task.is_open:
        task.closed_at = None


@tasks_bp.route("/<int:task_id>/move", methods=["POST"])
@operator_required
def task_move(task_id: int):
    """Перенести задачу в другой статус — с доски и из карточки."""
    task = db.get_or_404(Task, task_id)
    status = (request.form.get("status") or "").strip()
    if status not in dict(TASK_STATUSES):
        flash("Неизвестный статус задачи.", "danger")
        return redirect(url_for("tasks.task_view", task_id=task.id))

    was_open = task.is_open
    _log(task, "status", task.status_title, dict(TASK_STATUSES)[status])
    task.status = status
    _touch_closed(task, was_open)
    db.session.commit()
    return redirect(request.form.get("back") or
                    url_for("tasks.task_view", task_id=task.id))


@tasks_bp.route("/<int:task_id>/assign", methods=["POST"])
@operator_required
def task_assign(task_id: int):
    """Быстро взять задачу на себя или снять исполнителя."""
    task = db.get_or_404(Task, task_id)
    raw = request.form.get("assignee_id", "")
    new_id = int(raw) if raw.isdigit() and int(raw) else None

    _log(task, "assignee", _assignee_name(task.assignee_id),
         _assignee_name(new_id))
    task.assignee_id = new_id
    db.session.commit()
    return redirect(request.form.get("back") or
                    url_for("tasks.task_view", task_id=task.id))


@tasks_bp.route("/<int:task_id>/delete", methods=["POST"])
@operator_required
def task_delete(task_id: int):
    task = db.get_or_404(Task, task_id)
    key = task.key
    db.session.delete(task)
    db.session.commit()
    flash(f"Задача {key} удалена.", "success")
    return redirect(url_for("tasks.board"))



# --- Быстрое добавление прямо в колонке -----------------------------------

@tasks_bp.route("/quick", methods=["POST"])
@operator_required
def task_quick():
    """Создать задачу одной строкой, не уходя с доски.

    Постановщику обычно хватает названия, исполнителя и срока — полная форма
    для этого слишком тяжёлая.
    """
    form = QuickTaskForm()
    form.assignee_id.choices = [(0, "—")] + [(u.id, u.display_name)
                                             for u in _people()]
    if not form.validate_on_submit():
        flash("Не удалось создать задачу: проверьте название.", "danger")
        return redirect(_board_url())

    status = form.status.data if form.status.data in dict(TASK_STATUSES) \
        else TASK_BACKLOG
    task = Task(
        number=_next_number(),
        title=form.title.data.strip(),
        status=status,
        priority=form.priority.data or "normal",
        assignee_id=form.assignee_id.data or None,
        reporter_id=current_user.id,
        due_date=form.due_date.data,
    )
    db.session.add(task)
    db.session.flush()
    _log(task, "created", "", task.key)
    db.session.commit()
    flash(f"Задача {task.key} создана.", "success")
    return redirect(_board_url())


def _board_url() -> str:
    back = request.form.get("back") or ""
    if back.startswith("/"):
        return back
    return url_for("tasks.board")


# --- Пункты выполнения ----------------------------------------------------

@tasks_bp.route("/<int:task_id>/checklist", methods=["POST"])
@operator_required
def checklist_add(task_id: int):
    task = db.get_or_404(Task, task_id)
    form = ChecklistForm()
    if not form.validate_on_submit():
        flash("Введите текст пункта.", "danger")
        return redirect(url_for("tasks.task_view", task_id=task.id))

    # Несколько пунктов за раз: постановщику удобнее вставить список целиком.
    added = 0
    last = db.session.query(func.max(TaskChecklistItem.position)).filter_by(
        task_id=task.id
    ).scalar() or 0
    for line in (form.text.data or "").splitlines():
        line = line.strip().lstrip("-•*").strip()
        if not line:
            continue
        last += 1
        added += 1
        db.session.add(TaskChecklistItem(task_id=task.id, text=line[:500],
                                         position=last))
    if added:
        _log(task, "checklist", "", f"добавлено пунктов: {added}")
    db.session.commit()
    return redirect(url_for("tasks.task_view", task_id=task.id))


@tasks_bp.route("/checklist/<int:item_id>/toggle", methods=["POST"])
@operator_required
def checklist_toggle(item_id: int):
    item = db.get_or_404(TaskChecklistItem, item_id)
    item.is_done = not item.is_done
    item.done_at = datetime.utcnow() if item.is_done else None
    item.done_by_id = current_user.id if item.is_done else None

    task = item.task
    # Взялись за первый пункт — задача явно в работе, не надо это делать руками.
    if item.is_done and task.status in (TASK_BACKLOG, TASK_TODO):
        _log(task, "status", task.status_title, dict(TASK_STATUSES)[TASK_PROGRESS])
        task.status = TASK_PROGRESS
    db.session.commit()

    if request.form.get("ajax"):
        return {"done": item.is_done, "percent": task.checklist_percent}
    return redirect(url_for("tasks.task_view", task_id=item.task_id))


@tasks_bp.route("/checklist/<int:item_id>/delete", methods=["POST"])
@operator_required
def checklist_delete(item_id: int):
    item = db.get_or_404(TaskChecklistItem, item_id)
    task_id = item.task_id
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for("tasks.task_view", task_id=task_id))


# --- Моя работа -----------------------------------------------------------

@tasks_bp.route("/my")
@login_required
def my_work():
    """Личная очередь: что горит, что сегодня, что дальше.

    Отвечает на вопрос исполнителя «за что браться сейчас» — на общей доске
    это тонет среди чужих задач.
    """
    today = date.today()
    week = today + timedelta(days=7)
    mine = (
        Task.query.filter(Task.assignee_id == current_user.id,
                          Task.status != TASK_DONE)
        .all()
    )
    mine.sort(key=lambda t: (TASK_PRIORITY_ORDER.get(t.priority, 9),
                             t.due_date or date.max, -t.number))

    groups = [
        ("Просрочено", [t for t in mine if t.due_date and t.due_date < today]),
        ("Сегодня", [t for t in mine if t.due_date == today]),
        ("На этой неделе",
         [t for t in mine if t.due_date and today < t.due_date <= week]),
        ("Позже", [t for t in mine if t.due_date and t.due_date > week]),
        ("Без срока", [t for t in mine if not t.due_date]),
    ]

    # Что поставили мне, но я ещё не брал: сюда стоит заглянуть первым делом.
    fresh = [t for t in mine if t.status in (TASK_BACKLOG, TASK_TODO)]
    # Задачи, где я постановщик и жду результата.
    waiting = (
        Task.query.filter(Task.reporter_id == current_user.id,
                          Task.assignee_id != current_user.id,
                          Task.status != TASK_DONE)
        .order_by(Task.due_date.is_(None), Task.due_date)
        .all()
    )

    return render_template(
        "tasks/my.html",
        groups=[(title, items) for title, items in groups if items],
        total=len(mine),
        fresh=len(fresh),
        waiting=waiting,
        updates=_recent_updates(),
    )


def _recent_updates(limit: int = 20) -> list:
    """Изменения в задачах, которые касаются меня.

    Свои же правки не показываем: сотруднику интересно, что сделали другие.
    """
    return (
        TaskEvent.query.join(Task, TaskEvent.task_id == Task.id)
        .filter(TaskEvent.user_id != current_user.id)
        .filter(or_(Task.assignee_id == current_user.id,
                    Task.reporter_id == current_user.id))
        .order_by(TaskEvent.created_at.desc())
        .limit(limit)
        .all()
    )


@tasks_bp.route("/my/seen", methods=["POST"])
@login_required
def mark_seen():
    """Отметить изменения просмотренными — гасит счётчик «что нового»."""
    current_user.tasks_seen_at = datetime.utcnow()
    db.session.commit()
    return redirect(url_for("tasks.my_work"))


# --- Загрузка команды -----------------------------------------------------

@tasks_bp.route("/workload")
@login_required
def workload():
    """Кто чем занят и у кого горит — взгляд постановщика."""
    today = date.today()
    rows = []
    for person in _people():
        tasks = Task.query.filter(Task.assignee_id == person.id,
                                  Task.status != TASK_DONE).all()
        rows.append({
            "user": person,
            "total": len(tasks),
            "in_progress": sum(1 for t in tasks if t.status == TASK_PROGRESS),
            "overdue": sum(1 for t in tasks
                           if t.due_date and t.due_date < today),
            "critical": sum(1 for t in tasks if t.priority == "critical"),
            "soon": sum(1 for t in tasks if t.due_date
                        and today <= t.due_date <= today + timedelta(days=3)),
        })
    rows.sort(key=lambda r: (-r["overdue"], -r["total"]))

    unassigned = (
        Task.query.filter(Task.assignee_id.is_(None), Task.status != TASK_DONE)
        .order_by(Task.due_date.is_(None), Task.due_date)
        .all()
    )
    return render_template("tasks/workload.html", rows=rows,
                           unassigned=unassigned, people=_people())
