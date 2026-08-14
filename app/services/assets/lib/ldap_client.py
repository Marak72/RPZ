"""Чтение Active Directory через LDAP.

Только чтение. Здесь нет и не должно появиться ни одной операции записи:
учётная запись сервиса выдана с правами просмотра, и портал не должен уметь
менять каталог даже по ошибке.

Почему Global Catalog. Домен разнесён по области: контроллеров два десятка,
часть закрыта межсетевым экраном, и объект компьютера лежит в том сайте, где
стоит сама машина. Обычный LDAP (389) отвечает только за свой домен и вернёт
«не найдено» для чужого сайта. Глобальный каталог (3268) хранит частичную
копию всего леса, поэтому один запрос находит машину, где бы она ни стояла.
Набор атрибутов в нём урезан, но всё нужное — имя, ОС, описание, дата входа —
в него входит.

Почему NTLM, а не Kerberos. Kerberos потребовал бы keytab и настроенный
krb5.conf на сервере портала; NTLM-бинд работает с обычной парой «логин —
пароль» из настроек сервиса, а по сети всё равно идёт не пароль, а отклик.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

#: Атрибуты объекта компьютера, которые нам интересны. Просить «всё» нельзя:
#: у объекта их под сотню, и на выгрузке домена это лишние мегабайты.
COMPUTER_ATTRS = (
    "cn",
    "dNSHostName",
    "distinguishedName",
    "description",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "lastLogonTimestamp",
    "whenCreated",
    "managedBy",
)

USER_ATTRS = (
    "sAMAccountName",
    "displayName",
    "distinguishedName",
    "mail",
    "department",
    "title",
    "telephoneNumber",
    "physicalDeliveryOfficeName",
    "userAccountControl",
)

#: Бит «учётная запись отключена» в userAccountControl.
_UAC_DISABLED = 0x0002

#: Начало отсчёта времени Windows (FILETIME) — 1601 год.
_FILETIME_EPOCH = datetime(1601, 1, 1)


class LdapError(Exception):
    """Ошибка обращения к каталогу — текст показывается оператору как есть."""


@dataclass
class LdapConfig:
    host: str = ""
    port: int = 3268
    use_ssl: bool = False
    base_dn: str = ""
    username: str = ""          # DOMAIN\\user либо user@domain
    password: str = ""
    timeout: int = 20

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.username and self.password)


@dataclass
class AdComputer:
    name: str = ""
    fqdn: str = ""
    dn: str = ""
    description: str = ""
    os: str = ""
    os_version: str = ""
    enabled: bool = True
    last_logon: datetime | None = None
    when_created: datetime | None = None
    managed_by: str = ""

    @property
    def ou_path(self) -> str:
        """Читаемый путь размещения: «Тюмень / Отдел кадров / Компьютеры».

        Для аналитика это самое ценное поле после имени: по нему сразу видно
        чья это машина и в каком подразделении стоит.
        """
        return ou_from_dn(self.dn)


@dataclass
class AdUser:
    login: str = ""
    display_name: str = ""
    dn: str = ""
    mail: str = ""
    department: str = ""
    title: str = ""
    phone: str = ""
    office: str = ""
    enabled: bool = True

    @property
    def ou_path(self) -> str:
        return ou_from_dn(self.dn)


def ou_from_dn(dn: str) -> str:
    """Собрать путь подразделений из DN, отбросив сам объект и домен."""
    if not dn:
        return ""
    parts = []
    for chunk in _split_dn(dn):
        key, _, value = chunk.partition("=")
        if key.strip().upper() in ("OU", "CN") and value:
            parts.append(value.strip())
    # Первый элемент — сам объект (CN=PC-01), он в пути не нужен.
    if len(parts) > 1:
        parts = parts[1:]
    return " / ".join(reversed(parts))


def _split_dn(dn: str) -> list[str]:
    """Разбить DN по запятым, не считая экранированных (``\\,``)."""
    parts, current, escaped = [], [], False
    for char in dn:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            current.append(char)
            continue
        if char == ",":
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current))
    return parts


def base_dn_from_domain(domain: str) -> str:
    """«adm72.local» → «DC=adm72,DC=local» — чтобы не заполнять вручную."""
    parts = [p for p in (domain or "").strip().strip(".").split(".") if p]
    return ",".join("DC=" + p for p in parts)


def escape_filter(value: str) -> str:
    """Экранировать значение для LDAP-фильтра (RFC 4515).

    Без этого имя со звёздочкой или скобкой меняет смысл запроса — то же
    самое, что подстановка в SQL.
    """
    out = []
    for char in value or "":
        if char in "\\*()\0":
            out.append("\\%02x" % ord(char))
        else:
            out.append(char)
    return "".join(out)


def _filetime(value) -> datetime | None:
    """lastLogonTimestamp приходит либо числом FILETIME, либо уже датой."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=number // 10)
    except OverflowError:
        return None


def _text(entry, attr: str) -> str:
    value = entry.get(attr)
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if value is None:
        return ""
    return str(value).strip()


def _number(entry, attr: str) -> int:
    try:
        return int(_text(entry, attr) or 0)
    except ValueError:
        return 0


def _as_datetime(entry, attr: str) -> datetime | None:
    value = entry.get(attr)
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    return _filetime(value)


def computer_from_entry(entry: dict) -> AdComputer:
    """Собрать объект компьютера из словаря атрибутов LDAP."""
    return AdComputer(
        name=_text(entry, "cn"),
        fqdn=_text(entry, "dNSHostName"),
        dn=_text(entry, "distinguishedName"),
        description=_text(entry, "description"),
        os=_text(entry, "operatingSystem"),
        os_version=_text(entry, "operatingSystemVersion"),
        enabled=not bool(_number(entry, "userAccountControl") & _UAC_DISABLED),
        last_logon=_as_datetime(entry, "lastLogonTimestamp"),
        when_created=_as_datetime(entry, "whenCreated"),
        managed_by=_text(entry, "managedBy"),
    )


def user_from_entry(entry: dict) -> AdUser:
    return AdUser(
        login=_text(entry, "sAMAccountName"),
        display_name=_text(entry, "displayName"),
        dn=_text(entry, "distinguishedName"),
        mail=_text(entry, "mail"),
        department=_text(entry, "department"),
        title=_text(entry, "title"),
        phone=_text(entry, "telephoneNumber"),
        office=_text(entry, "physicalDeliveryOfficeName"),
        enabled=not bool(_number(entry, "userAccountControl") & _UAC_DISABLED),
    )


class LdapClient:
    """Соединение с каталогом. Открывается на время операции и закрывается.

    Держать соединение постоянно нельзя: рабочих процессов несколько, а
    контроллер закрывает простаивающие сессии сам, и следующий запрос
    упал бы на давно установленном соединении.
    """

    def __init__(self, config: LdapConfig) -> None:
        self.config = config
        self._conn = None

    # --- соединение -------------------------------------------------------

    def connect(self):
        if self._conn is not None:
            return self._conn
        if not self.config.is_configured:
            raise LdapError(
                "Подключение к Active Directory не настроено: укажите "
                "контроллер, учётную запись и пароль в настройках сервиса."
            )
        ldap3, exceptions = _import_ldap3()
        server = ldap3.Server(
            self.config.host,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            get_info=ldap3.NONE,
            connect_timeout=self.config.timeout,
        )
        try:
            conn = ldap3.Connection(
                server,
                user=self.config.username,
                password=self.config.password,
                authentication=ldap3.NTLM,
                auto_bind=True,
                receive_timeout=self.config.timeout,
                read_only=True,       # запись запрещена на уровне библиотеки
            )
        except exceptions.LDAPBindError as exc:
            raise LdapError(
                "Контроллер домена отклонил вход: проверьте логин "
                "(нужен вид ДОМЕН\\пользователь) и пароль. %s" % exc
            ) from exc
        except exceptions.LDAPExceptionError as exc:
            raise LdapError(
                "Не удалось соединиться с %s:%s — %s"
                % (self.config.host, self.config.port, exc)
            ) from exc
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:  # noqa: BLE001 — соединение и так закрывается
                pass
            self._conn = None

    def __enter__(self) -> "LdapClient":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # --- поиск ------------------------------------------------------------

    def _search(self, ldap_filter: str, attrs, size_limit: int = 0) -> list[dict]:
        conn = self.connect()
        _, exceptions = _import_ldap3()
        try:
            conn.search(
                search_base=self.config.base_dn,
                search_filter=ldap_filter,
                attributes=list(attrs),
                size_limit=size_limit,
            )
        except exceptions.LDAPExceptionError as exc:
            raise LdapError("Каталог отклонил запрос: %s" % exc) from exc
        return [dict(entry.entry_attributes_as_dict) for entry in conn.entries]

    def find_computer(self, name: str) -> AdComputer | None:
        """Найти компьютер по короткому имени или FQDN."""
        clean = escape_filter((name or "").strip().rstrip("."))
        if not clean:
            return None
        short = clean.split(".", 1)[0]
        ldap_filter = (
            "(&(objectClass=computer)(|(cn=%s)(sAMAccountName=%s$)"
            "(dNSHostName=%s)))" % (short, short, clean)
        )
        rows = self._search(ldap_filter, COMPUTER_ATTRS, size_limit=5)
        return computer_from_entry(rows[0]) if rows else None

    def search_computers(self, text: str, limit: int = 100) -> list[AdComputer]:
        """Поиск по части имени или описания — для страницы поиска."""
        clean = escape_filter((text or "").strip())
        if not clean:
            return []
        ldap_filter = (
            "(&(objectClass=computer)(|(cn=*%s*)(dNSHostName=*%s*)"
            "(description=*%s*)))" % (clean, clean, clean)
        )
        rows = self._search(ldap_filter, COMPUTER_ATTRS, size_limit=limit)
        return [computer_from_entry(row) for row in rows]

    def iter_computers(self, page_size: int = 500):
        """Все компьютеры домена постранично — для полной выгрузки.

        Каталог не отдаёт больше тысячи записей за раз (MaxPageSize), поэтому
        обычный поиск по всему домену молча обрезался бы. Постраничный обход
        — единственный правильный способ выгрузить лес целиком.
        """
        conn = self.connect()
        ldap3, exceptions = _import_ldap3()
        try:
            entries = conn.extend.standard.paged_search(
                search_base=self.config.base_dn,
                search_filter="(objectClass=computer)",
                search_scope=ldap3.SUBTREE,
                attributes=list(COMPUTER_ATTRS),
                paged_size=page_size,
                generator=True,
            )
            for entry in entries:
                if entry.get("type") != "searchResEntry":
                    continue
                yield computer_from_entry(dict(entry.get("attributes") or {}))
        except exceptions.LDAPExceptionError as exc:
            raise LdapError("Каталог прервал выгрузку: %s" % exc) from exc

    def find_user(self, login: str) -> AdUser | None:
        clean = escape_filter((login or "").strip())
        if not clean:
            return None
        if "\\" in clean:
            clean = clean.rsplit("\\", 1)[1]
        ldap_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(|(sAMAccountName=%s)(userPrincipalName=%s)))" % (clean, clean)
        )
        rows = self._search(ldap_filter, USER_ATTRS, size_limit=5)
        return user_from_entry(rows[0]) if rows else None

    def resolve_dn(self, dn: str) -> AdUser | None:
        """Развернуть managedBy (это DN) в карточку сотрудника."""
        if not dn:
            return None
        rows = self._search(
            "(distinguishedName=%s)" % escape_filter(dn), USER_ATTRS, size_limit=2
        )
        return user_from_entry(rows[0]) if rows else None


def _import_ldap3():
    """Подтянуть ldap3 и внятно объяснить, если пакета нет.

    Библиотека нужна только этому сервису, поэтому импорт локальный: портал
    должен подниматься и без неё, просто с неработающим разделом AD.
    """
    try:
        import ldap3
        from ldap3.core import exceptions
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise LdapError(
            "Не установлена библиотека ldap3. Установите её в окружении "
            "портала: pip install ldap3"
        ) from exc
    return ldap3, exceptions
