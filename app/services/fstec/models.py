"""Модели сервиса «РПЗ ФСТЭК».

Главная сущность здесь — ПИСЬМО (:class:`Letter`), а не файл. У одного письма
ФСТЭК обычно несколько файлов: само письмо и приложения к нему с перечнем
индикаторов. Раньше каждый файл заводился отдельной записью, из-за чего одно
письмо выглядело в архиве как несколько разных, а номер письма дублировался
в каждой строке.

Схема связей::

    Letter (номер + дата)
      ├── LetterFile      файлы письма: само письмо и приложения
      └── индикаторы      BlockEntry / UrlEntry / IocHash

Индикатор связан с письмами связью многие-ко-многим: один и тот же домен
приходит в нескольких письмах, и аналитику важно видеть все источники, а не
только первый. Раньше повторный индикатор просто отбрасывался, и связь со
вторым письмом терялась.
"""
from datetime import datetime

from ...core.extensions import db

# Статусы индикатора.
STATUS_NEW = "new"        # распознан, ещё не выгружен на сервер
STATUS_IN_RPZ = "in_rpz"  # присутствует в считанном файле RPZ
STATUS_PUSHED = "pushed"  # выгружен на сервер этим приложением
# Решения аналитика: индикатор разобран и блокировать его не нужно.
STATUS_FALSE_POSITIVE = "fp"    # ложное срабатывание, в письме ошибка
STATUS_IGNORED = "ignored"      # легитимный ресурс, блокировать нельзя

STATUSES = (
    (STATUS_NEW, "не в RPZ"),
    (STATUS_IN_RPZ, "в RPZ"),
    (STATUS_PUSHED, "выгружен"),
    (STATUS_FALSE_POSITIVE, "ложное срабатывание"),
    (STATUS_IGNORED, "не блокируем"),
)
# Статусы «разобрано, блокировать не нужно» — такие индикаторы не попадают
# ни в выгрузку, ни в счётчик ожидающих.
STATUS_DISMISSED = (STATUS_FALSE_POSITIVE, STATUS_IGNORED)

# Результаты выгрузки в BIND.
PUSH_SUCCESS = "success"
PUSH_FAILED = "failed"
PUSH_DRY_RUN = "dry_run"
PUSH_ROLLED_BACK = "rolled_back"

# Типы хешей-индикаторов.
HASH_TYPES = ("sha256", "sha1", "md5")


def _link_table(name: str, entry_table: str) -> db.Table:
    """Связь «индикатор ↔ письмо».

    ``file_id`` хранит файл, из которого индикатор пришёл: внутри одного
    письма полезно знать, приехал ли домен из самого письма или из приложения.
    """
    return db.Table(
        name,
        db.Column("entry_id", db.Integer,
                  db.ForeignKey(f"{entry_table}.id", ondelete="CASCADE"),
                  primary_key=True),
        db.Column("letter_id", db.Integer,
                  db.ForeignKey("letters.id", ondelete="CASCADE"),
                  primary_key=True),
        db.Column("file_id", db.Integer,
                  db.ForeignKey("letter_files.id", ondelete="SET NULL")),
    )


block_entry_letters = _link_table("block_entry_letters", "block_entries")
url_entry_letters = _link_table("url_entry_letters", "url_entries")
ioc_hash_letters = _link_table("ioc_hash_letters", "ioc_hashes")
email_entry_letters = _link_table("email_entry_letters", "email_entries")


class Letter(db.Model):
    """Письмо ФСТЭК: номер, дата и всё, что к нему пришло."""

    __tablename__ = "letters"

    id = db.Column(db.Integer, primary_key=True)
    # Номер письма как в документе, напр. «240/24/1234».
    number = db.Column(db.String(120), nullable=False, default="", index=True)
    # Нормализованный номер: по нему письма склеиваются при загрузке скопом
    # (см. normalize_number). Пустой — если номер распознать не удалось.
    number_key = db.Column(db.String(120), nullable=False, default="", index=True)
    letter_date = db.Column(db.Date, index=True)
    subject = db.Column(db.String(500), nullable=False, default="")
    notes = db.Column(db.String(1000), nullable=False, default="")

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    user = db.relationship("User")
    files = db.relationship(
        "LetterFile",
        back_populates="letter",
        cascade="all, delete-orphan",
        order_by="LetterFile.id",
    )

    @property
    def title(self) -> str:
        """Как называть письмо в интерфейсе."""
        if self.number:
            return f"№ {self.number}"
        if self.files:
            return self.files[0].filename
        return f"Письмо #{self.id}"

    @property
    def main_file(self):
        """Файл, который показываем как основной (первый пригодный к просмотру)."""
        for f in self.files:
            if f.is_primary:
                return f
        for f in self.files:
            if f.is_pdf:
                return f
        return self.files[0] if self.files else None

    def __repr__(self) -> str:
        return f"<Letter {self.number or self.id} ({len(self.files)} файл.)>"


class LetterFile(db.Model):
    """Файл, приложенный к письму: само письмо или приложение к нему."""

    __tablename__ = "letter_files"

    id = db.Column(db.Integer, primary_key=True)
    letter_id = db.Column(db.Integer, db.ForeignKey("letters.id"), nullable=False,
                          index=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False, default="")
    content_type = db.Column(db.String(100), nullable=False, default="")
    file_size = db.Column(db.Integer, nullable=False, default=0)
    # sha256 содержимого — по нему ловим повторную загрузку того же файла.
    sha256 = db.Column(db.String(64), nullable=False, default="", index=True)
    # Основной файл письма (а не приложение). Ставится при разборе.
    is_primary = db.Column(db.Boolean, nullable=False, default=False)
    # Сколько индикаторов дал именно этот файл.
    entries_found = db.Column(db.Integer, nullable=False, default=0)
    # Текст разбора не сохраняем, но причину неудачи — да: без неё непонятно,
    # почему у приложения ноль индикаторов.
    parse_error = db.Column(db.String(500), nullable=False, default="")
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    letter = db.relationship("Letter", back_populates="files")
    user = db.relationship("User")

    @property
    def is_pdf(self) -> bool:
        return (self.content_type or "").endswith("pdf") or \
            (self.filename or "").lower().endswith(".pdf")

    @property
    def size_kb(self) -> int:
        return round((self.file_size or 0) / 1024)

    def __repr__(self) -> str:
        return f"<LetterFile {self.filename}>"


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


class _FromLetters:
    """Общее поведение индикаторов, приезжающих из писем."""

    @property
    def letter_numbers(self) -> str:
        """Номера писем-источников одной строкой — для таблиц и CSV."""
        return ", ".join(
            letter.number or f"#{letter.id}"
            for letter in sorted(self.letters, key=lambda x: (x.letter_date or
                                                             x.created_at.date()))
        )

    @property
    def first_letter(self):
        """Письмо, в котором индикатор встретился впервые."""
        if not self.letters:
            return None
        return min(self.letters, key=lambda x: x.id)


class BlockEntry(_FromLetters, db.Model):
    """Домен или IP-адрес — кандидат на блокировку."""

    __tablename__ = "block_entries"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(500), unique=True, nullable=False, index=True)
    entry_type = db.Column(db.String(10), nullable=False)  # domain / ip
    status = db.Column(db.String(20), nullable=False, default=STATUS_NEW, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.Text, default="")
    # Когда запись была выгружена в RPZ-зону этим приложением.
    pushed_at = db.Column(db.DateTime)
    # Откуда взялась запись: letter (из письма) / manual (добавлена вручную).
    source = db.Column(db.String(20), nullable=False, default="letter")
    # Решение аналитика по статусам «ложное срабатывание» / «не блокируем»:
    # без причины такой статус нечитаем через месяц.
    decision_note = db.Column(db.String(500), nullable=False, default="")
    decided_at = db.Column(db.DateTime)
    decided_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    letters = db.relationship(
        "Letter", secondary=block_entry_letters,
        backref=db.backref("block_entries", lazy="dynamic"),
    )

    @property
    def vt(self):
        """Отчёт VirusTotal для этого значения (если проверялось)."""
        from ...core.models import VtReport
        return VtReport.query.filter_by(value=self.value).first()

    @property
    def is_pushable(self) -> bool:
        """В RPZ можно выгружать только домены (IP блокируются на МЭ).

        Разобранные индикаторы («ложное срабатывание», «не блокируем») в
        выгрузку не идут — решение аналитика важнее факта попадания в письмо.
        """
        return self.entry_type == "domain" and self.status not in STATUS_DISMISSED

    @property
    def status_title(self) -> str:
        return dict(STATUSES).get(self.status, self.status)

    def __repr__(self) -> str:
        return f"<BlockEntry {self.value} ({self.status})>"


class UrlEntry(_FromLetters, db.Model):
    """Ссылка С ПУТЁМ из письма ФСТЭК.

    RPZ работает на уровне DNS-имён и не умеет блокировать конкретные пути,
    поэтому такие индикаторы хранятся отдельно — их блокируют на прокси/WAF.

    Хост такой ссылки кандидатом на блокировку НЕ становится: вредоносна
    страница, а не сайт целиком. Он сохраняется в ``host``, чтобы аналитик
    видел его рядом и мог отправить в блокировку сам, если сайт вредоносен
    целиком.
    """

    __tablename__ = "url_entries"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(2000), unique=True, nullable=False)
    host = db.Column(db.String(500), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.String(500), default="")

    letters = db.relationship(
        "Letter", secondary=url_entry_letters,
        backref=db.backref("url_entries", lazy="dynamic"),
    )

    def __repr__(self) -> str:
        return f"<UrlEntry {self.value[:60]}…>"


class EmailEntry(_FromLetters, db.Model):
    """Адрес электронной почты из письма ФСТЭК.

    Хранится отдельно по той же причине, что и ссылки с путями: домен из
    адреса кандидатом на блокировку не становится. Фишинг рассылают с
    mail.ru, gmail.com и с бесплатных хостингов — закрыть их в RPZ значит
    оставить отдел без почты, а вреда от этого больше, чем от самой рассылки.

    Домен сохраняется в ``host`` рядом с адресом: если он всё-таки вредоносен
    целиком — как подделка вида ``roskomnadsor.ru``, встречающаяся только в
    адресе отправителя, — аналитик отправляет его в блокировку одной кнопкой.
    """

    __tablename__ = "email_entries"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(320), unique=True, nullable=False, index=True)
    host = db.Column(db.String(255), nullable=False, default="", index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.String(500), default="")

    letters = db.relationship(
        "Letter", secondary=email_entry_letters,
        backref=db.backref("email_entries", lazy="dynamic"),
    )

    def __repr__(self) -> str:
        return f"<EmailEntry {self.value}>"


class IocHash(_FromLetters, db.Model):
    """Хеш вредоносного файла из письма ФСТЭК (для SIEM и антивируса)."""

    __tablename__ = "ioc_hashes"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(128), unique=True, nullable=False, index=True)
    hash_type = db.Column(db.String(10), nullable=False)  # sha256 / sha1 / md5
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.String(500), default="")

    letters = db.relationship(
        "Letter", secondary=ioc_hash_letters,
        backref=db.backref("ioc_hashes", lazy="dynamic"),
    )

    def __repr__(self) -> str:
        return f"<IocHash {self.hash_type}:{self.value[:16]}…>"


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
