"""Модели ядра портала: люди, доступы, настройки, фоновые задания.

Здесь живёт только то, что общее для всех сервисов. Модели самих сервисов
лежат рядом с их кодом: app/services/<сервис>/models.py.
"""
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager

# Роли пользователей.
ROLE_ADMIN = "admin"        # всё то же, что оператор, плюс управление учётными записями
ROLE_OPERATOR = "operator"  # изменения в доступных сервисах: загрузка, выгрузка, настройки
ROLE_MANAGER = "manager"    # только просмотр

ROLES = (
    (ROLE_ADMIN, "администратор"),
    (ROLE_OPERATOR, "оператор"),
    (ROLE_MANAGER, "просмотр"),
)

# Результаты обращений к внешним системам.
JOB_SUCCESS = "success"
JOB_FAILED = "failed"
# Состояния фоновых заданий: до JOB_SUCCESS/JOB_FAILED задание живёт здесь.
JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_ACTIVE_STATUSES = (JOB_QUEUED, JOB_RUNNING)

# Виды фоновых заданий.
JOB_KIND_SIEM = "siem_lookup"
JOB_KIND_SKYDNS = "skydns_sync"
JOB_KIND_ASSETS_DHCP = "assets_dhcp_sync"
JOB_KIND_ASSETS_AD = "assets_ad_sync"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=ROLE_OPERATOR)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Реквизиты сотрудника — чтобы в журналах было видно живого человека.
    full_name = db.Column(db.String(200), nullable=False, default="")
    email = db.Column(db.String(200), nullable=False, default="")
    position = db.Column(db.String(200), nullable=False, default="")
    # Отключённая учётная запись остаётся в базе (на неё ссылаются журналы),
    # но войти по ней нельзя.
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_login_at = db.Column(db.DateTime)
    # Когда сотрудник последний раз смотрел изменения в своих задачах —
    # по этой отметке считается счётчик «что нового».
    tasks_seen_at = db.Column(db.DateTime)

    grants = db.relationship(
        "UserService",
        backref="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def is_operator(self) -> bool:
        """Может ли менять данные. Администратор — тоже оператор."""
        return self.role in (ROLE_OPERATOR, ROLE_ADMIN)

    @property
    def is_active(self) -> bool:
        """Flask-Login не пускает неактивных пользователей."""
        return bool(self.is_enabled)

    @property
    def role_title(self) -> str:
        return dict(ROLES).get(self.role, self.role)

    @property
    def display_name(self) -> str:
        return self.full_name or self.username

    def allowed_services(self) -> set:
        """ID сервисов, доступных пользователю."""
        return {g.service_id for g in self.grants}

    def can_use(self, service_id: str) -> bool:
        """Виден ли пользователю сервис. Администратору доступно всё."""
        if self.is_admin:
            return True
        return service_id in self.allowed_services()

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


class UserService(db.Model):
    """Доступ учётной записи к сервису портала.

    Права выдаёт администратор: у сотрудника в боковой панели видны только
    разрешённые сервисы, а их страницы закрыты на уровне blueprint.
    """

    __tablename__ = "user_services"
    __table_args__ = (
        db.UniqueConstraint("user_id", "service_id", name="uq_user_service"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False,
                        index=True)
    service_id = db.Column(db.String(40), nullable=False, index=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<UserService {self.user_id} -> {self.service_id}>"


class VtReport(db.Model):
    """Результат проверки индикатора в VirusTotal.

    Привязан к значению (домен/IP), поэтому один отчёт обслуживает
    и кандидата, и запись RPZ с тем же значением.
    """

    __tablename__ = "vt_reports"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(500), unique=True, nullable=False, index=True)
    kind = db.Column(db.String(10), nullable=False, default="domain")  # domain / ip
    malicious = db.Column(db.Integer, nullable=False, default=0)
    suspicious = db.Column(db.Integer, nullable=False, default=0)
    harmless = db.Column(db.Integer, nullable=False, default=0)
    undetected = db.Column(db.Integer, nullable=False, default=0)
    reputation = db.Column(db.Integer, nullable=False, default=0)
    total_engines = db.Column(db.Integer, nullable=False, default=0)
    permalink = db.Column(db.String(500), default="")
    checked_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    checked_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    error = db.Column(db.String(500), default="")

    @property
    def verdict(self) -> str:
        """Итоговая оценка для наглядного отображения."""
        if self.error:
            return "error"
        if self.malicious >= 5:
            return "malicious"
        if self.malicious >= 1:
            return "suspicious"
        if self.suspicious >= 3:
            return "suspicious"
        return "clean"

    @property
    def score(self) -> str:
        return f"{self.malicious}/{self.total_engines}" if self.total_engines else "—"

    def __repr__(self) -> str:
        return f"<VtReport {self.value} {self.score}>"


class AppSetting(db.Model):
    """Настройки приложения вида ключ-значение (секреты хранятся зашифрованно)."""

    __tablename__ = "app_settings"

    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text, default="")
    is_secret = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<AppSetting {self.key}>"


class BackgroundJob(db.Model):
    """Длительная работа, вынесенная из запроса в фоновый поток.

    Поиск конечных хостов в SIEM — это отдельный запрос на каждый домен, и
    пачка доменов легко занимает минуты. Пока работа шла прямо в обработчике
    запроса, браузер просто висел на кнопке, а веб-сервер мог оборвать
    соединение по таймауту. Теперь обработчик заводит запись здесь, отдаёт
    страницу сразу, а поток дописывает прогресс — портал показывает его
    плашкой и не мешает работать дальше.

    Состояние живёт в базе, а не в памяти процесса: за gunicorn работает
    несколько рабочих процессов, и запрос о ходе задания может прийти не в
    тот процесс, который его выполняет.
    """

    __tablename__ = "background_jobs"

    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(40), nullable=False, index=True)
    # Сервис портала, к которому относится задание (для плашки и ссылок).
    service_id = db.Column(db.String(40), nullable=False, default="")
    title = db.Column(db.String(200), nullable=False, default="")
    status = db.Column(db.String(20), nullable=False, default=JOB_QUEUED, index=True)

    total = db.Column(db.Integer, nullable=False, default=0)
    processed = db.Column(db.Integer, nullable=False, default=0)
    failed = db.Column(db.Integer, nullable=False, default=0)
    result_count = db.Column(db.Integer, nullable=False, default=0)

    # Что делается прямо сейчас — показывается в плашке под заголовком.
    detail = db.Column(db.String(300), default="")
    # Итог работы или текст ошибки.
    message = db.Column(db.Text, default="")
    # Куда вести оператора по клику на завершившееся задание.
    target_url = db.Column(db.String(500), default="")

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    # Признак жизни: поток обновляет его на каждом шаге. Если процесс умер,
    # задание навсегда осталось бы «выполняется» — по этой метке видно, что
    # его больше некому доделать.
    heartbeat_at = db.Column(db.DateTime)
    # Когда оператор закрыл плашку завершённого задания.
    dismissed_at = db.Column(db.DateTime)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    user = db.relationship("User")

    @property
    def is_active(self) -> bool:
        return self.status in JOB_ACTIVE_STATUSES

    @property
    def percent(self) -> int:
        if not self.total:
            return 0
        return min(100, int(self.processed * 100 / self.total))

    @property
    def status_title(self) -> str:
        return {
            JOB_QUEUED: "в очереди",
            JOB_RUNNING: "выполняется",
            JOB_SUCCESS: "готово",
            JOB_FAILED: "ошибка",
        }.get(self.status, self.status)

    def as_dict(self) -> dict:
        """Представление для плашки прогресса в браузере."""
        return {
            "id": self.id,
            "kind": self.kind,
            "service": self.service_id,
            "title": self.title,
            "status": self.status,
            "status_title": self.status_title,
            "active": self.is_active,
            "total": self.total,
            "processed": self.processed,
            "failed": self.failed,
            "found": self.result_count,
            "percent": self.percent,
            "detail": self.detail or "",
            "message": self.message or "",
            "url": self.target_url or "",
        }

    def __repr__(self) -> str:
        return f"<BackgroundJob {self.kind} {self.status} {self.processed}/{self.total}>"
