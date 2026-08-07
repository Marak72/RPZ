"""Модели базы данных."""
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager

# Роли пользователей.
ROLE_OPERATOR = "operator"  # полный доступ: загрузка, SSH-обновление, настройки
ROLE_MANAGER = "manager"    # только просмотр

# Статусы кандидатов из писем ФСТЭК.
STATUS_NEW = "new"        # распознан, ещё не выгружен на сервер
STATUS_IN_RPZ = "in_rpz"  # присутствует в считанном файле RPZ
STATUS_PUSHED = "pushed"  # выгружен на сервер этим приложением

# Результаты выгрузки в BIND.
PUSH_SUCCESS = "success"
PUSH_FAILED = "failed"
PUSH_DRY_RUN = "dry_run"
PUSH_ROLLED_BACK = "rolled_back"


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

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_operator(self) -> bool:
        return self.role == ROLE_OPERATOR

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


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
