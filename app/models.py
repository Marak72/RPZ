"""Модели базы данных."""
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

# Статусы кандидатов из писем ФСТЭК.
STATUS_NEW = "new"        # распознан, ещё не выгружен на сервер
STATUS_IN_RPZ = "in_rpz"  # присутствует в считанном файле RPZ
STATUS_PUSHED = "pushed"  # выгружен на сервер этим приложением

# Результаты выгрузки в BIND.
PUSH_SUCCESS = "success"
PUSH_FAILED = "failed"
PUSH_DRY_RUN = "dry_run"
PUSH_ROLLED_BACK = "rolled_back"

# Статусы разбора обращения на вредоносный домен (сервис SkyDNS).
THREAT_NEW = "new"                # только что приехал из SkyDNS, не разбирали
THREAT_INVESTIGATING = "working"  # ищем хосты / разбираемся
THREAT_BLOCKED = "blocked"        # отправлен в блокировку RPZ
THREAT_FALSE_POSITIVE = "fp"      # ложное срабатывание, категория неверна
THREAT_CLOSED = "closed"          # разобрано, действий не требуется

THREAT_STATUSES = (
    (THREAT_NEW, "новый"),
    (THREAT_INVESTIGATING, "в работе"),
    (THREAT_BLOCKED, "заблокирован"),
    (THREAT_FALSE_POSITIVE, "ложное"),
    (THREAT_CLOSED, "закрыт"),
)

# Откуда приехала запись об угрозе.
THREAT_SOURCE_API = "api"     # автоматическая выгрузка из API SkyDNS
THREAT_SOURCE_CSV = "csv"     # импорт выгрузки из личного кабинета
THREAT_SOURCE_MANUAL = "manual"

# Результаты обращений к внешним системам (SkyDNS, SIEM).
JOB_SUCCESS = "success"
JOB_FAILED = "failed"
# Состояния фоновых заданий: до JOB_SUCCESS/JOB_FAILED задание живёт здесь.
JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_ACTIVE_STATUSES = (JOB_QUEUED, JOB_RUNNING)

# Виды фоновых заданий.
JOB_KIND_SIEM = "siem_lookup"
JOB_KIND_SKYDNS = "skydns_sync"

# Откуда узнали про конечный хост.
HOST_SOURCE_SIEM = "siem"      # группировка событий MaxPatrol SIEM
HOST_SOURCE_SKYDNS = "skydns"  # метод get_devices_activity SkyDNS

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


class SshServer(db.Model):
    """Учётная запись (УЗ) для подключения к DNS-серверу по SSH.

    Пароль хранится зашифрованным (Fernet) в password_enc.
    """

    __tablename__ = "ssh_servers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, default="DNS-сервер")
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=22)
    username = db.Column(db.String(120), nullable=False)
    password_enc = db.Column(db.Text, nullable=False)
    zone_file_path = db.Column(
        db.String(500), nullable=False, default="/var/named/master/rpz.block.db"
    )
    # Имя зоны для named-checkzone и `rndc reload <zone>`.
    zone_name = db.Column(db.String(255), nullable=False, default="rpz.block")
    # Выполнять файловые операции на сервере через sudo -n (если нет прав на файл).
    use_sudo = db.Column(db.Boolean, nullable=False, default=False)
    # Выполнять ТОЛЬКО `rndc reload <зона>` через sudo -n. Вызывается напрямую,
    # без обёртки sh -c, чтобы подходило узкое правило в sudoers:
    #   rpzbot ALL=(root) NOPASSWD: /usr/sbin/rndc reload rpz.block
    sudo_rndc = db.Column(db.Boolean, nullable=False, default=False)
    # Проверять зону через named-checkzone перед установкой (настоятельно да).
    validate_zone = db.Column(db.Boolean, nullable=False, default=True)
    # Перезагружать зону через rndc reload после установки.
    reload_zone = db.Column(db.Boolean, nullable=False, default=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self) -> str:
        return f"<SshServer {self.username}@{self.host}:{self.port}>"


class RpzSnapshot(db.Model):
    """Снимок считанного по SSH файла RPZ-зоны."""

    __tablename__ = "rpz_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("ssh_servers.id"))
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    fetched_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    raw_content = db.Column(db.Text, nullable=False, default="")
    entry_count = db.Column(db.Integer, nullable=False, default=0)

    server = db.relationship("SshServer")
    user = db.relationship("User")
    entries = db.relationship(
        "RpzEntry",
        backref="snapshot",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<RpzSnapshot {self.id} {self.fetched_at} ({self.entry_count})>"


class RpzEntry(db.Model):
    """Одна запись блокировки из снимка RPZ-зоны."""

    __tablename__ = "rpz_entries"

    id = db.Column(db.Integer, primary_key=True)
    snapshot_id = db.Column(
        db.Integer, db.ForeignKey("rpz_snapshots.id"), nullable=False, index=True
    )
    domain = db.Column(db.String(500), nullable=False, index=True)
    is_wildcard = db.Column(db.Boolean, nullable=False, default=False)
    record_type = db.Column(db.String(10), nullable=False)  # A / CNAME
    target = db.Column(db.String(255), nullable=False, default="")
    action = db.Column(db.String(20), nullable=False)  # block / redirect

    def __repr__(self) -> str:
        return f"<RpzEntry {self.domain} {self.record_type} {self.action}>"


class Document(db.Model):
    """Письмо ФСТЭК: сам файл письма и все извлечённые из него индикаторы."""

    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    entries_found = db.Column(db.Integer, nullable=False, default=0)
    notes = db.Column(db.String(500), default="")

    # Реквизиты письма для поиска и отчётности.
    letter_number = db.Column(db.String(120), default="")
    letter_date = db.Column(db.Date)

    # Сохранённый файл письма (для просмотра/скачивания).
    stored_name = db.Column(db.String(255), default="")   # имя файла в хранилище
    content_type = db.Column(db.String(100), default="")
    file_size = db.Column(db.Integer, default=0)
    # Отдельно приложенный PDF (если разбирался .docx, а смотреть удобнее PDF).
    pdf_stored_name = db.Column(db.String(255), default="")
    pdf_original_name = db.Column(db.String(255), default="")
    pdf_size = db.Column(db.Integer, default=0)

    user = db.relationship("User")
    entries = db.relationship("BlockEntry", backref="document", lazy="dynamic")

    @property
    def is_pdf(self) -> bool:
        return (self.content_type or "").endswith("pdf")

    @property
    def viewable_pdf(self) -> bool:
        """Есть ли PDF, который можно показать прямо в браузере."""
        return bool(self.pdf_stored_name) or self.is_pdf

    def __repr__(self) -> str:
        return f"<Document {self.filename} ({self.entries_found})>"


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


class BlockEntry(db.Model):
    """Кандидат на блокировку, извлечённый из письма ФСТЭК."""

    __tablename__ = "block_entries"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(500), unique=True, nullable=False, index=True)
    entry_type = db.Column(db.String(10), nullable=False)  # domain / ip
    document_id = db.Column(db.Integer, db.ForeignKey("documents.id"))
    status = db.Column(db.String(20), nullable=False, default=STATUS_NEW)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.Text, default="")
    # Когда запись была выгружена в RPZ-зону этим приложением.
    pushed_at = db.Column(db.DateTime)
    # Откуда взялась запись: letter (из письма) / manual (добавлена вручную).
    source = db.Column(db.String(20), nullable=False, default="letter")

    @property
    def vt(self):
        """Отчёт VirusTotal для этого значения (если проверялось)."""
        return VtReport.query.filter_by(value=self.value).first()

    @property
    def is_pushable(self) -> bool:
        """В RPZ можно выгружать только домены (IP блокируются на межсетевом экране)."""
        return self.entry_type == "domain"

    def __repr__(self) -> str:
        return f"<BlockEntry {self.value} ({self.status})>"


class UrlEntry(db.Model):
    """Ссылка С ПУТЁМ из письма ФСТЭК.

    RPZ работает на уровне DNS-имён и не умеет блокировать конкретные пути,
    поэтому такие индикаторы хранятся отдельно — их блокируют на прокси/WAF.
    Хост из такой ссылки при этом попадает в BlockEntry как обычный домен.
    """

    __tablename__ = "url_entries"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(2000), unique=True, nullable=False)
    host = db.Column(db.String(500), nullable=False, index=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.String(500), default="")

    document = db.relationship("Document")

    def __repr__(self) -> str:
        return f"<UrlEntry {self.value[:60]}…>"


class PushLog(db.Model):
    """Журнал выгрузок в RPZ-зону на боевом DNS-сервере."""

    __tablename__ = "push_logs"

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("ssh_servers.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), nullable=False)  # success/failed/dry_run/rolled_back
    entries_count = db.Column(db.Integer, nullable=False, default=0)
    domains = db.Column(db.Text, default="")       # список выгруженных доменов
    backup_path = db.Column(db.String(500), default="")
    old_serial = db.Column(db.String(32), default="")
    new_serial = db.Column(db.String(32), default="")
    message = db.Column(db.Text, default="")       # подробный лог шагов

    server = db.relationship("SshServer")
    user = db.relationship("User")

    def __repr__(self) -> str:
        return f"<PushLog {self.id} {self.status} ({self.entries_count})>"


class ThreatDomain(db.Model):
    """Домен «опасной» категории, на который обращались из организации.

    Приезжает из статистики SkyDNS (или импортом CSV). Дальше по домену
    выполняется запрос в MaxPatrol SIEM, который отвечает на главный вопрос:
    какие именно конечные хосты организации туда ходили.
    """

    __tablename__ = "threat_domains"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(500), unique=True, nullable=False, index=True)
    # Основная (первая опасная) категория SkyDNS и читаемые названия всех.
    category = db.Column(db.String(120), nullable=False, default="", index=True)
    category_title = db.Column(db.String(200), nullable=False, default="")
    # Все категории домена из ответа API — список id через запятую.
    cat_ids = db.Column(db.String(200), nullable=False, default="")
    # Профиль/подразделение SkyDNS, в статистике которого встретился домен.
    profile = db.Column(db.String(200), nullable=False, default="")

    requests_count = db.Column(db.Integer, nullable=False, default=0)
    blocks_count = db.Column(db.Integer, nullable=False, default=0)

    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    status = db.Column(db.String(20), nullable=False, default=THREAT_NEW, index=True)
    source = db.Column(db.String(20), nullable=False, default=THREAT_SOURCE_API)
    notes = db.Column(db.Text, default="")

    # Когда последний раз ходили в SIEM за конечными хостами.
    siem_checked_at = db.Column(db.DateTime)
    siem_hosts_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    hosts = db.relationship(
        "ThreatHost",
        backref="threat",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @property
    def vt(self):
        """Отчёт VirusTotal для этого домена (общий с сервисом ФСТЭК)."""
        return VtReport.query.filter_by(value=self.domain).first()

    @property
    def block_entry(self):
        """Запись в кандидатах на блокировку RPZ, если домен уже отправлен туда."""
        return BlockEntry.query.filter_by(value=self.domain).first()

    @property
    def status_title(self) -> str:
        return dict(THREAT_STATUSES).get(self.status, self.status)

    def __repr__(self) -> str:
        return f"<ThreatDomain {self.domain} ({self.category})>"


class SkydnsCategory(db.Model):
    """Справочник категорий SkyDNS.

    Заполняется из ``get_categories_activity``: у каждой категории есть флаг
    ``is_dangerous``, поэтому список «опасных» не нужно вести руками.
    """

    __tablename__ = "skydns_categories"

    id = db.Column(db.Integer, primary_key=True)  # id категории в SkyDNS
    title = db.Column(db.String(200), nullable=False, default="")
    is_dangerous = db.Column(db.Boolean, nullable=False, default=False, index=True)
    # Ручное переопределение: категорию можно принудительно включить в разбор
    # или исключить из него, не дожидаясь изменений на стороне SkyDNS.
    track_override = db.Column(db.Boolean)
    # Счётчики последней выгрузки — чтобы видеть, откуда идёт основной поток.
    requests = db.Column(db.Integer, nullable=False, default=0)
    blocks = db.Column(db.Integer, nullable=False, default=0)
    domains_count = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    @property
    def is_tracked(self) -> bool:
        """Следим ли за категорией: ручная настройка важнее флага SkyDNS."""
        if self.track_override is not None:
            return self.track_override
        return self.is_dangerous

    def __repr__(self) -> str:
        return f"<SkydnsCategory {self.id} {self.title}>"


class ThreatHost(db.Model):
    """Конечный хост организации, обращавшийся к вредоносному домену.

    Источников два:

      * ``siem``   — группировка событий MaxPatrol SIEM по ``dst.host``;
      * ``skydns`` — метод ``get_devices_activity``: устройства с агентом
        SkyDNS видны сразу, без обращения к SIEM.
    """

    __tablename__ = "threat_hosts"
    __table_args__ = (
        db.UniqueConstraint("threat_id", "address", name="uq_threat_host"),
    )

    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(
        db.Integer, db.ForeignKey("threat_domains.id"), nullable=False, index=True
    )
    # Значение поля группировки: как правило IP-адрес, иногда имя хоста.
    address = db.Column(db.String(255), nullable=False, index=True)
    hostname = db.Column(db.String(255), nullable=False, default="")
    events_count = db.Column(db.Integer, nullable=False, default=0)
    # Откуда узнали про хост: siem / skydns.
    source = db.Column(db.String(20), nullable=False, default="siem", index=True)
    # Токен устройства SkyDNS (0 — трафик через шлюз, агента нет).
    device_token = db.Column(db.String(40), nullable=False, default="")
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    found_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    @property
    def is_ip(self) -> bool:
        parts = (self.address or "").split(".")
        return len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255 for p in parts
        )

    def __repr__(self) -> str:
        return f"<ThreatHost {self.address} ({self.events_count})>"


class SiemQueryLog(db.Model):
    """Журнал обращений к MaxPatrol SIEM за конечными хостами."""

    __tablename__ = "siem_query_logs"

    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.Integer, db.ForeignKey("threat_domains.id"), index=True)
    domain = db.Column(db.String(500), nullable=False, default="")
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), nullable=False, default=JOB_SUCCESS)
    hosts_found = db.Column(db.Integer, nullable=False, default=0)
    events_total = db.Column(db.Integer, nullable=False, default=0)
    # Фильтр, который реально ушёл в SIEM — чтобы можно было повторить руками.
    query_filter = db.Column(db.Text, default="")
    period_from = db.Column(db.DateTime)
    period_to = db.Column(db.DateTime)
    message = db.Column(db.Text, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    user = db.relationship("User")
    threat = db.relationship("ThreatDomain")

    def __repr__(self) -> str:
        return f"<SiemQueryLog {self.domain} {self.status} ({self.hosts_found})>"


class SkydnsSyncLog(db.Model):
    """Журнал выгрузок статистики из SkyDNS."""

    __tablename__ = "skydns_sync_logs"

    id = db.Column(db.Integer, primary_key=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), nullable=False, default=JOB_SUCCESS)
    source = db.Column(db.String(20), nullable=False, default=THREAT_SOURCE_API)
    period_from = db.Column(db.Date)
    period_to = db.Column(db.Date)
    domains_total = db.Column(db.Integer, nullable=False, default=0)
    domains_new = db.Column(db.Integer, nullable=False, default=0)
    message = db.Column(db.Text, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    user = db.relationship("User")

    def __repr__(self) -> str:
        return f"<SkydnsSyncLog {self.started_at} {self.status}>"


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


class IocHash(db.Model):
    """Хеш-индикатор компрометации (sha256/sha1/md5) из письма ФСТЭК.

    Хеши не блокируются в RPZ — это IoC для систем мониторинга (SIEM),
    поэтому хранятся отдельно от BlockEntry.
    """

    __tablename__ = "ioc_hashes"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(64), unique=True, nullable=False, index=True)
    hash_type = db.Column(db.String(10), nullable=False)  # sha256 / sha1 / md5
    document_id = db.Column(db.Integer, db.ForeignKey("documents.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.String(500), default="")

    document = db.relationship("Document")

    def __repr__(self) -> str:
        return f"<IocHash {self.hash_type}:{self.value[:12]}…>"


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
