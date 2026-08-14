"""Таблицы сервиса «Узлы сети».

Две главные сущности намеренно разведены, потому что это разные вещи:

  * :class:`NetworkHost` — что известно про **адрес**. Источник — аренды DHCP:
    только там есть связка «адрес → имя → MAC». Адрес живёт своей жизнью,
    аренда меняется, и вчерашний владелец адреса — уже другая машина.
  * :class:`AdComputer` — что известно про **машину**. Источник — Active
    Directory: подразделение, описание, ОС, дата последнего входа. У машины
    может не быть аренды (статический адрес), у аренды может не быть объекта
    в каталоге (сетевое оборудование в домен не заводят).

Связывает их :attr:`NetworkHost.ad_computer_id` — по совпадению имени. Если
связи нет, обе половины всё равно доступны поиску по отдельности: лучше
показать половину правды, чем не найти ничего.

:class:`HostObservation` хранит историю смен: именно она отвечает на вопрос
«а кто держал этот адрес неделю назад», ради которого сервис и затевался.
"""
from __future__ import annotations

from datetime import datetime

from ...core.extensions import db
from .lib import classify
from .lib.ipaddr import ip_to_int

#: Откуда узнали про адрес.
SOURCE_DHCP = "dhcp"
SOURCE_AD = "ad"
SOURCE_MANUAL = "manual"
SOURCE_LOOKUP = "lookup"      # завели при точечной проверке адреса

SOURCE_TITLES = {
    SOURCE_DHCP: "аренда DHCP",
    SOURCE_AD: "Active Directory",
    SOURCE_MANUAL: "заведён вручную",
    SOURCE_LOOKUP: "точечная проверка",
}


class AdComputer(db.Model):
    """Объект компьютера из Active Directory (зеркало, только чтение)."""

    __tablename__ = "asset_ad_computers"

    id = db.Column(db.Integer, primary_key=True)
    # Короткое имя в нижнем регистре — по нему идёт связывание с арендой.
    name = db.Column(db.String(255), nullable=False, unique=True, index=True)
    fqdn = db.Column(db.String(255), nullable=False, default="")
    dn = db.Column(db.Text, nullable=False, default="")
    ou_path = db.Column(db.String(500), nullable=False, default="", index=True)
    description = db.Column(db.String(1000), nullable=False, default="")
    os = db.Column(db.String(255), nullable=False, default="")
    os_version = db.Column(db.String(100), nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    managed_by = db.Column(db.Text, nullable=False, default="")
    last_logon = db.Column(db.DateTime)
    when_created = db.Column(db.DateTime)
    kind = db.Column(db.String(20), nullable=False, default=classify.KIND_UNKNOWN,
                     index=True)
    synced_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    hosts = db.relationship("NetworkHost", back_populates="ad_computer")

    @property
    def kind_title(self) -> str:
        return classify.title(self.kind)

    def __repr__(self) -> str:
        return f"<AdComputer {self.name}>"


class NetworkHost(db.Model):
    """Что известно про адрес в сети.

    Ключ — сам адрес: сервис отвечает на вопрос «чей это адрес», и именно его
    аналитик вводит в поиск.
    """

    __tablename__ = "asset_hosts"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, unique=True, index=True)
    # Числовое представление адреса: сортировка и попадание в область DHCP.
    # Строкой «10.10.9.1» больше «10.10.10.1», и список выглядел бы случайным.
    ip_int = db.Column(db.BigInteger, nullable=False, default=0, index=True)

    hostname = db.Column(db.String(255), nullable=False, default="", index=True)
    mac = db.Column(db.String(17), nullable=False, default="", index=True)

    # Аренда DHCP.
    dhcp_server = db.Column(db.String(255), nullable=False, default="")
    scope_id = db.Column(db.String(45), nullable=False, default="", index=True)
    lease_state = db.Column(db.String(40), nullable=False, default="")
    lease_expires_at = db.Column(db.DateTime)

    source = db.Column(db.String(20), nullable=False, default=SOURCE_DHCP,
                       index=True)
    kind = db.Column(db.String(20), nullable=False, default=classify.KIND_UNKNOWN,
                     index=True)

    ad_computer_id = db.Column(
        db.Integer, db.ForeignKey("asset_ad_computers.id"), index=True
    )
    ad_computer = db.relationship("AdComputer", back_populates="hosts")

    notes = db.Column(db.Text, nullable=False, default="")

    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    # Когда адрес в последний раз проверяли точечно, а не выгрузкой.
    checked_at = db.Column(db.DateTime)

    observations = db.relationship(
        "HostObservation", back_populates="host", cascade="all, delete-orphan",
        order_by="HostObservation.seen_at.desc()",
    )

    def touch_ip(self) -> None:
        self.ip_int = ip_to_int(self.ip)

    @property
    def is_reservation(self) -> bool:
        return "reservation" in (self.lease_state or "").lower()

    @property
    def lease_active(self) -> bool:
        return (self.lease_state or "").lower().startswith("active")

    @property
    def lease_expired(self) -> bool:
        """Срок аренды прошёл — значит машины по этому адресу может не быть."""
        return bool(self.lease_expires_at
                    and self.lease_expires_at < datetime.utcnow())

    @property
    def display_name(self) -> str:
        """Имя узла. Аренда важнее каталога: она свежее.

        Порядок именно такой, потому что аренда меняется чаще, чем зеркало AD
        обновляется выгрузкой. Если взять имя из каталога, у только что
        переехавшего адреса в шапке окажется прежняя машина.
        """
        if self.hostname:
            return self.hostname
        if self.ad_computer is not None:
            return self.ad_computer.name
        return ""

    @property
    def kind_title(self) -> str:
        return classify.title(self.kind)

    @property
    def kind_badge(self) -> str:
        return classify.badge(self.kind)

    @property
    def is_infrastructure(self) -> bool:
        return classify.is_infrastructure(self.kind)

    @property
    def source_title(self) -> str:
        return SOURCE_TITLES.get(self.source, self.source)

    def __repr__(self) -> str:
        return f"<NetworkHost {self.ip} {self.hostname}>"


class HostObservation(db.Model):
    """Смена того, что стоит за адресом.

    Пишется не на каждую выгрузку, а только когда что-то изменилось: имя,
    MAC или состояние аренды. Иначе история распухла бы до бесполезности —
    выгрузка идёт по расписанию, а меняется адрес раз в недели.
    """

    __tablename__ = "asset_observations"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("asset_hosts.id"),
                        nullable=False, index=True)
    host = db.relationship("NetworkHost", back_populates="observations")

    seen_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    hostname = db.Column(db.String(255), nullable=False, default="")
    mac = db.Column(db.String(17), nullable=False, default="")
    lease_state = db.Column(db.String(40), nullable=False, default="")
    # Человеческое описание изменения: «имя: pc-01 → pc-07».
    change = db.Column(db.String(500), nullable=False, default="")

    def __repr__(self) -> str:
        return f"<HostObservation {self.host_id} {self.seen_at}>"


class DhcpScope(db.Model):
    """Область DHCP: карта «какой сервер отвечает за какой диапазон».

    Нужна, чтобы точечная проверка адреса шла сразу на нужный сервер, а не
    опрашивала два десятка площадок подряд.
    """

    __tablename__ = "asset_dhcp_scopes"
    __table_args__ = (
        db.UniqueConstraint("server", "scope_id", name="uq_asset_scope"),
    )

    id = db.Column(db.Integer, primary_key=True)
    server = db.Column(db.String(255), nullable=False, index=True)
    scope_id = db.Column(db.String(45), nullable=False)
    name = db.Column(db.String(255), nullable=False, default="")
    mask = db.Column(db.String(45), nullable=False, default="")
    start_ip = db.Column(db.String(45), nullable=False, default="")
    end_ip = db.Column(db.String(45), nullable=False, default="")
    start_int = db.Column(db.BigInteger, nullable=False, default=0, index=True)
    end_int = db.Column(db.BigInteger, nullable=False, default=0, index=True)
    state = db.Column(db.String(40), nullable=False, default="")
    lease_count = db.Column(db.Integer, nullable=False, default=0)
    synced_at = db.Column(db.DateTime, default=datetime.utcnow)

    def touch_range(self) -> None:
        self.start_int = ip_to_int(self.start_ip)
        self.end_int = ip_to_int(self.end_ip)

    @property
    def is_active(self) -> bool:
        return (self.state or "").lower() == "active"

    def __repr__(self) -> str:
        return f"<DhcpScope {self.server} {self.scope_id}>"


class AssetLookup(db.Model):
    """Журнал обращений: кто и что искал, нашлось ли.

    Ведётся не ради контроля, а ради работы: при разборе инцидента важно
    видеть, что этот адрес уже смотрели неделю назад и что тогда нашли.
    """

    __tablename__ = "asset_lookups"

    id = db.Column(db.Integer, primary_key=True)
    # Именно ``term``, а не ``query``: имя ``query`` у модели занято самим
    # Flask-SQLAlchemy (``Model.query``), и колонка с таким именем молча
    # ломает любой запрос к этой таблице.
    term = db.Column(db.String(255), nullable=False, index=True)
    # Что именно ввели: ip / hostname / mac / text.
    query_kind = db.Column(db.String(20), nullable=False, default="text")
    # Живая проверка во внешних системах или поиск по своей базе.
    is_live = db.Column(db.Boolean, nullable=False, default=False)
    found = db.Column(db.Boolean, nullable=False, default=False)
    result = db.Column(db.String(500), nullable=False, default="")
    error = db.Column(db.String(1000), nullable=False, default="")

    host_id = db.Column(db.Integer, db.ForeignKey("asset_hosts.id"), index=True)
    host = db.relationship("NetworkHost")

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    user = db.relationship("User")

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self) -> str:
        return f"<AssetLookup {self.term} found={self.found}>"


class AssetSyncLog(db.Model):
    """Журнал выгрузок из DHCP и AD."""

    __tablename__ = "asset_sync_logs"

    id = db.Column(db.Integer, primary_key=True)
    # dhcp / ad
    source = db.Column(db.String(20), nullable=False, index=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime)
    servers = db.Column(db.Integer, nullable=False, default=0)
    scopes = db.Column(db.Integer, nullable=False, default=0)
    received = db.Column(db.Integer, nullable=False, default=0)
    created = db.Column(db.Integer, nullable=False, default=0)
    updated = db.Column(db.Integer, nullable=False, default=0)
    ok = db.Column(db.Boolean, nullable=False, default=False)
    message = db.Column(db.Text, nullable=False, default="")

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User")

    @property
    def duration(self) -> str:
        if not self.finished_at or not self.started_at:
            return ""
        seconds = int((self.finished_at - self.started_at).total_seconds())
        if seconds < 60:
            return "%d с" % seconds
        return "%d мин %d с" % (seconds // 60, seconds % 60)

    def __repr__(self) -> str:
        return f"<AssetSyncLog {self.source} {self.started_at}>"
