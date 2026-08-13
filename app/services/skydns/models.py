"""Модели сервиса «Угрозы SkyDNS»."""
from datetime import datetime

from ...core.extensions import db
from ...core.models import JOB_SUCCESS

# Статусы разбора обращения на вредоносный домен.
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

# Откуда узнали про конечный хост.
HOST_SOURCE_SIEM = "siem"      # группировка событий MaxPatrol SIEM
HOST_SOURCE_SKYDNS = "skydns"  # метод get_devices_activity SkyDNS


class ThreatDomain(db.Model):
    """Домен «опасной» категории, на который обращались из организации.

    Приезжает из статистики SkyDNS (или импортом CSV). Дальше по домену
    выполняется запрос в MaxPatrol SIEM, который отвечает на главный вопрос:
    какие именно конечные хосты организации туда ходили.
    """

    __tablename__ = "threat_domains"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(500), unique=True, nullable=False, index=True)
    # Корневой (регистрируемый) домен: si21if1u2.afd.footprintdns.com ->
    # footprintdns.com. Хранится рядом, а не считается на лету, чтобы по нему
    # работали свёрнутый список, фильтр и группировка средствами БД.
    root_domain = db.Column(db.String(300), nullable=False, default="", index=True)
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
        from ...core.models import VtReport

        return VtReport.query.filter_by(value=self.domain).first()

    @property
    def subdomain(self) -> str:
        """Часть имени слева от корня — то, чем отличаются однотипные имена."""
        from .lib.domains import subdomain_part

        return subdomain_part(self.domain)

    @property
    def cat_id_list(self) -> list:
        """Категории домена числами: в базе они лежат строкой через запятую."""
        return [int(part) for part in (self.cat_ids or "").split(",")
                if part.strip().lstrip("-").isdigit()]

    @property
    def block_entry(self):
        """Запись в кандидатах на блокировку RPZ, если домен уже отправлен туда.

        Единственная связь с соседним сервисом — импорт локальный, чтобы
        зависимость не превращалась в обязательную при загрузке моделей.
        """
        from ..fstec.models import BlockEntry

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


class DomainExclusion(db.Model):
    """Правило «этот домен вредоносным не считать».

    Категории SkyDNS срабатывают и на служебном трафике: телеметрия,
    обновления, CDN-имена вида ``si21if1u2.afd.footprintdns.com``. Разбирать
    их заново на каждой выгрузке — потерянное время, а удалять поштучно
    бессмысленно: завтра приедет ещё сотня таких же имён.

    Поэтому исключение — это правило, а не отметка на записи. Оно работает
    и вперёд (домен не попадает в список при выгрузке), и назад (уже
    загруженные совпавшие домены убираются при сохранении правила).
    """

    __tablename__ = "domain_exclusions"

    id = db.Column(db.Integer, primary_key=True)
    # Либо точное имя, либо *.example.com — домен со всеми поддоменами.
    pattern = db.Column(db.String(300), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(500), nullable=False, default="")
    # Сколько записей убрало правило при создании — видно, что оно не зря.
    removed_count = db.Column(db.Integer, nullable=False, default=0)
    # Сколько раз правило отсеяло домен на последующих выгрузках.
    hits_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = db.relationship("User")

    @property
    def is_wildcard(self) -> bool:
        return self.pattern.startswith("*.")

    def __repr__(self) -> str:
        return f"<DomainExclusion {self.pattern}>"
