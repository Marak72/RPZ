"""Модели базы данных."""
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager

# Роли пользователей.
ROLE_OPERATOR = "operator"  # полный доступ: загрузка, SSH-обновление, настройки
ROLE_MANAGER = "manager"    # только просмотр

# Статусы кандидатов из писем ФСТЭК.
STATUS_NEW = "new"        # распознан, ещё не сверён/не на сервере
STATUS_IN_RPZ = "in_rpz"  # уже присутствует в считанном файле RPZ
STATUS_PUSHED = "pushed"  # выгружен на сервер (финальная фаза)


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
    """Загруженное письмо ФСТЭК (.docx/.odt)."""

    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    entries_found = db.Column(db.Integer, nullable=False, default=0)
    notes = db.Column(db.String(500), default="")

    user = db.relationship("User")
    entries = db.relationship("BlockEntry", backref="document", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Document {self.filename} ({self.entries_found})>"


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
    notes = db.Column(db.String(500), default="")

    def __repr__(self) -> str:
        return f"<BlockEntry {self.value} ({self.status})>"


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
