"""Модели сервиса «Задачи отдела»."""
from datetime import datetime

from ...core.extensions import db

# Задачи отдела. Порядок статусов — это порядок колонок на доске.
TASK_BACKLOG = "backlog"
TASK_TODO = "todo"
TASK_PROGRESS = "in_progress"
TASK_REVIEW = "review"
TASK_DONE = "done"

TASK_STATUSES = (
    (TASK_BACKLOG, "Входящие"),
    (TASK_TODO, "К работе"),
    (TASK_PROGRESS, "В работе"),
    (TASK_REVIEW, "На проверке"),
    (TASK_DONE, "Готово"),
)
TASK_OPEN_STATUSES = (TASK_BACKLOG, TASK_TODO, TASK_PROGRESS, TASK_REVIEW)

TASK_PRIORITIES = (
    ("critical", "Критический"),
    ("high", "Высокий"),
    ("normal", "Обычный"),
    ("low", "Низкий"),
)
# Порядок сортировки: критические задачи наверху доски.
TASK_PRIORITY_ORDER = {"critical": 0, "high": 1, "normal": 2, "low": 3}


class Task(db.Model):
    """Задача отдела.

    Номер (``SOC-12``) выдаётся при создании и не меняется: на него ссылаются
    в переписке и в отчётах.
    """

    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer, unique=True, nullable=False, index=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, default="")

    status = db.Column(db.String(20), nullable=False, default=TASK_BACKLOG,
                       index=True)
    priority = db.Column(db.String(20), nullable=False, default="normal",
                         index=True)
    # К какому сервису портала относится задача (fstec / skydns / пусто).
    service_id = db.Column(db.String(40), nullable=False, default="", index=True)

    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    due_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime)

    assignee = db.relationship("User", foreign_keys=[assignee_id])
    reporter = db.relationship("User", foreign_keys=[reporter_id])
    comments = db.relationship(
        "TaskComment", backref="task", cascade="all, delete-orphan",
        lazy="dynamic",
    )
    checklist = db.relationship(
        "TaskChecklistItem", backref="task", cascade="all, delete-orphan",
        lazy="dynamic", order_by="TaskChecklistItem.position",
    )
    events = db.relationship(
        "TaskEvent", backref="task", cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @property
    def key(self) -> str:
        return f"SOC-{self.number}"

    @property
    def status_title(self) -> str:
        return dict(TASK_STATUSES).get(self.status, self.status)

    @property
    def priority_title(self) -> str:
        return dict(TASK_PRIORITIES).get(self.priority, self.priority)

    @property
    def is_open(self) -> bool:
        return self.status != TASK_DONE

    @property
    def is_overdue(self) -> bool:
        """Просрочена ли задача. Закрытые не считаются просроченными."""
        if not self.due_date or not self.is_open:
            return False
        return self.due_date < datetime.utcnow().date()

    @property
    def days_left(self):
        """Сколько дней до срока: отрицательное — просрочка, None — срока нет."""
        if not self.due_date:
            return None
        return (self.due_date - datetime.utcnow().date()).days

    @property
    def due_label(self) -> str:
        """Срок словами: «сегодня», «завтра», «просрочена на 3 дня»."""
        left = self.days_left
        if left is None:
            return ""
        if not self.is_open:
            return self.due_date.strftime("%d.%m")
        if left < 0:
            days = abs(left)
            tail = "день" if days % 10 == 1 and days % 100 != 11 else (
                "дня" if 2 <= days % 10 <= 4 and not 12 <= days % 100 <= 14
                else "дней"
            )
            return f"просрочена на {days} {tail}"
        if left == 0:
            return "сегодня"
        if left == 1:
            return "завтра"
        if left <= 7:
            return f"через {left} дн."
        return self.due_date.strftime("%d.%m")

    @property
    def checklist_total(self) -> int:
        return self.checklist.count()

    @property
    def checklist_done(self) -> int:
        return self.checklist.filter_by(is_done=True).count()

    @property
    def checklist_percent(self) -> int:
        total = self.checklist_total
        return int(self.checklist_done * 100 / total) if total else 0

    def __repr__(self) -> str:
        return f"<Task {self.key} {self.status}>"


class TaskChecklistItem(db.Model):
    """Пункт выполнения задачи.

    Главное средство против «я думал, надо было другое»: постановщик
    расписывает шаги, исполнитель отмечает сделанное, и прогресс виден на
    карточке — спрашивать «как там?» не нужно.
    """

    __tablename__ = "task_checklist"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("tasks.id"), nullable=False,
                        index=True)
    text = db.Column(db.String(500), nullable=False, default="")
    is_done = db.Column(db.Boolean, nullable=False, default=False)
    position = db.Column(db.Integer, nullable=False, default=0)
    done_at = db.Column(db.DateTime)
    done_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    done_by = db.relationship("User")

    def __repr__(self) -> str:
        return f"<TaskChecklistItem {self.task_id} {self.text[:20]}>"


class TaskComment(db.Model):
    """Комментарий к задаче."""

    __tablename__ = "task_comments"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("tasks.id"), nullable=False,
                        index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    body = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship("User")

    def __repr__(self) -> str:
        return f"<TaskComment {self.task_id}>"


class TaskEvent(db.Model):
    """Запись в истории задачи: кто и что поменял.

    Без истории непонятно, почему задача переехала в другую колонку и когда
    сменился исполнитель.
    """

    __tablename__ = "task_events"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("tasks.id"), nullable=False,
                        index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    field = db.Column(db.String(40), nullable=False, default="")
    old_value = db.Column(db.String(300), default="")
    new_value = db.Column(db.String(300), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship("User")

    def __repr__(self) -> str:
        return f"<TaskEvent {self.task_id} {self.field}>"
