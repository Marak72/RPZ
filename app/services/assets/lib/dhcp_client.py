"""Чтение аренд Windows DHCP через WinRM.

Почему именно так. У службы DHCP от Microsoft нет ни LDAP-интерфейса, ни
HTTP-API: единственный поддерживаемый способ получить аренды — модуль
PowerShell ``DhcpServer``. Поэтому портал открывает сессию WinRM к самому
DHCP-серверу и выполняет там команды чтения.

Только чтение. Здесь выполняются исключительно команды ``Get-*``; список
разрешённых глаголов проверяется перед отправкой (см. :func:`_guard`). Даже
если в шаблон запроса когда-нибудь попадёт лишнее, до сервера оно не дойдёт.

Зачем нужен обратный DNS, которого нет. В этом домене PTR-записи заведены
только для серверов, у рабочих станций их нет — проверено на живых адресах.
Значит имя узла по адресу взять больше неоткуда: аренда DHCP остаётся
единственным источником связки «адрес — имя — MAC».
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime

from .ipaddr import normalize_mac, parse_ip

#: Разрешённые глаголы PowerShell. Всё остальное до сервера не уходит.
_ALLOWED_VERBS = ("Get-", "Import-Module", "ConvertTo-Json", "Select-Object")

#: Имя сервера: буквы, цифры, дефис, точка. Ничего, что могло бы вырваться
#: из кавычек в PowerShell.
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


class DhcpError(Exception):
    """Ошибка обращения к DHCP — текст показывается оператору как есть."""


@dataclass
class DhcpConfig:
    host: str = ""              # где выполнять команды (сервер с модулем DhcpServer)
    port: int = 5985
    use_ssl: bool = False
    username: str = ""          # DOMAIN\\user
    password: str = ""
    timeout: int = 60

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.username and self.password)


@dataclass
class DhcpServer:
    name: str = ""
    address: str = ""


@dataclass
class DhcpScopeInfo:
    scope_id: str = ""
    name: str = ""
    mask: str = ""
    start: str = ""
    end: str = ""
    state: str = ""


@dataclass
class DhcpLease:
    ip: str = ""
    hostname: str = ""
    mac: str = ""
    state: str = ""
    expires_at: datetime | None = None
    scope_id: str = ""
    server: str = ""

    @property
    def is_reservation(self) -> bool:
        return "reservation" in (self.state or "").lower()


def _guard(script: str) -> None:
    """Убедиться, что в сценарии нет ничего, кроме чтения."""
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("$"):
            continue
        if stripped.startswith("[Console]"):
            continue
        if not any(stripped.startswith(verb) for verb in _ALLOWED_VERBS):
            raise DhcpError(
                "Внутренняя ошибка: сервис пытается выполнить на DHCP-сервере "
                "команду, не являющуюся чтением (%s). Запрос не отправлен."
                % stripped.split()[0]
            )


def _safe_host(value: str) -> str:
    text = (value or "").strip()
    if not _SAFE_HOST.match(text):
        raise DhcpError("Недопустимое имя сервера DHCP: %r" % value)
    return text


def _safe_ip(value: str) -> str:
    text = parse_ip(value)
    if not text:
        raise DhcpError("Недопустимый адрес: %r" % value)
    return text


def _parse_ps_datetime(value) -> datetime | None:
    """Разобрать дату из ответа PowerShell.

    Сценарии просят формат ``s`` (2026-08-14T09:25:00), но старые сборки в
    отдельных случаях всё же отдают ``/Date(1755164700000)/`` — обрабатываем
    оба варианта, иначе срок аренды молча теряется.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    match = re.match(r"^/Date\((-?\d+)", text)
    if match:
        try:
            return datetime.utcfromtimestamp(int(match.group(1)) / 1000.0)
        except (ValueError, OverflowError, OSError):
            return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                "%d.%m.%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:26], fmt)
        except ValueError:
            continue
    return None


def _rows(raw: str) -> list[dict]:
    """Разобрать JSON от PowerShell в список словарей.

    Пустой вывод — это не ошибка, а «ничего не нашлось»: команда, не вернувшая
    объектов, печатает пустую строку.
    """
    text = (raw or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise DhcpError(
            "DHCP-сервер вернул неразборчивый ответ. Обычно это значит, что "
            "команда завершилась ошибкой раньше вывода. Начало ответа: %s"
            % text[:300]
        ) from exc
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def leases_from_rows(rows: list[dict], server: str = "",
                     scope_id: str = "") -> list[DhcpLease]:
    """Собрать аренды из разобранного ответа. Вынесено ради тестов."""
    out = []
    for row in rows:
        ip = parse_ip(str(row.get("IPAddress") or ""))
        if not ip:
            continue
        out.append(DhcpLease(
            ip=ip,
            hostname=(str(row.get("HostName") or "").strip().rstrip(".")),
            mac=normalize_mac(str(row.get("ClientId") or "")),
            state=str(row.get("AddressState") or "").strip(),
            expires_at=_parse_ps_datetime(row.get("LeaseExpiryTime")),
            scope_id=parse_ip(str(row.get("ScopeId") or "")) or scope_id,
            server=server,
        ))
    return out


def scopes_from_rows(rows: list[dict]) -> list[DhcpScopeInfo]:
    out = []
    for row in rows:
        scope_id = parse_ip(str(row.get("ScopeId") or ""))
        if not scope_id:
            continue
        out.append(DhcpScopeInfo(
            scope_id=scope_id,
            name=str(row.get("Name") or "").strip(),
            mask=parse_ip(str(row.get("SubnetMask") or "")),
            start=parse_ip(str(row.get("StartRange") or "")),
            end=parse_ip(str(row.get("EndRange") or "")),
            state=str(row.get("State") or "").strip(),
        ))
    return out


def servers_from_rows(rows: list[dict]) -> list[DhcpServer]:
    out = []
    for row in rows:
        name = str(row.get("DnsName") or "").strip().rstrip(".")
        address = parse_ip(str(row.get("IPAddress") or ""))
        if name or address:
            out.append(DhcpServer(name=name or address, address=address))
    return out


# --- сценарии PowerShell --------------------------------------------------
#
# ConvertTo-Json вызывается с -InputObject, а не через конвейер: конвейер
# разворачивает массив из одного элемента, и ответ на «нашлась ровно одна
# аренда» приезжал бы объектом вместо списка.

_PREAMBLE = (
    "$ErrorActionPreference='Stop'\n"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n"
    "Import-Module DhcpServer\n"
)

_SELECT_LEASE = (
    "Select-Object @{n='IPAddress';e={$_.IPAddress.IPAddressToString}},"
    "@{n='ScopeId';e={$_.ScopeId.IPAddressToString}},"
    "@{n='ClientId';e={[string]$_.ClientId}},"
    "@{n='HostName';e={[string]$_.HostName}},"
    "@{n='AddressState';e={[string]$_.AddressState}},"
    "@{n='LeaseExpiryTime';e={if($_.LeaseExpiryTime){"
    "$_.LeaseExpiryTime.ToString('s')}else{''}}}"
)

_SELECT_SCOPE = (
    "Select-Object @{n='ScopeId';e={$_.ScopeId.IPAddressToString}},"
    "@{n='SubnetMask';e={$_.SubnetMask.IPAddressToString}},"
    "@{n='Name';e={[string]$_.Name}},"
    "@{n='State';e={[string]$_.State}},"
    "@{n='StartRange';e={$_.StartRange.IPAddressToString}},"
    "@{n='EndRange';e={$_.EndRange.IPAddressToString}}"
)


class DhcpClient:
    """Сессия WinRM к серверу, где есть модуль DhcpServer."""

    def __init__(self, config: DhcpConfig) -> None:
        self.config = config
        self._session = None

    def _connect(self):
        if self._session is not None:
            return self._session
        if not self.config.is_configured:
            raise DhcpError(
                "Подключение к DHCP не настроено: укажите сервер, учётную "
                "запись и пароль в настройках сервиса."
            )
        winrm = _import_winrm()
        scheme = "https" if self.config.use_ssl else "http"
        endpoint = "%s://%s:%s/wsman" % (
            scheme, _safe_host(self.config.host), int(self.config.port)
        )
        self._session = winrm.Session(
            endpoint,
            auth=(self.config.username, self.config.password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=self.config.timeout + 10,
            operation_timeout_sec=self.config.timeout,
        )
        return self._session

    def close(self) -> None:
        self._session = None

    def __enter__(self) -> "DhcpClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def run(self, script: str) -> str:
        """Выполнить сценарий чтения и вернуть его вывод."""
        _guard(script)
        session = self._connect()
        try:
            result = session.run_ps(script)
        except Exception as exc:  # noqa: BLE001 — winrm бросает разное
            raise DhcpError(
                "Не удалось выполнить запрос на %s: %s. Проверьте, что WinRM "
                "включён и учётной записи разрешено подключение."
                % (self.config.host, exc)
            ) from exc
        if result.status_code != 0:
            error = (result.std_err or b"").decode("utf-8", "replace").strip()
            raise DhcpError(
                "DHCP-сервер отклонил запрос: %s"
                % (_short_ps_error(error) or "код %s" % result.status_code)
            )
        return (result.std_out or b"").decode("utf-8", "replace")

    # --- операции чтения --------------------------------------------------

    def list_servers(self) -> list[DhcpServer]:
        """Все авторизованные в домене DHCP-серверы.

        Один запрос вместо ручного перечисления двух десятков площадок: список
        ведёт сама AD, и он всегда актуален.
        """
        script = _PREAMBLE + (
            "ConvertTo-Json -Compress -Depth 3 -InputObject "
            "@(Get-DhcpServerInDC | Select-Object DnsName,"
            "@{n='IPAddress';e={$_.IPAddress.IPAddressToString}})\n"
        )
        return servers_from_rows(_rows(self.run(script)))

    def list_scopes(self, server: str) -> list[DhcpScopeInfo]:
        script = _PREAMBLE + (
            "ConvertTo-Json -Compress -Depth 3 -InputObject "
            "@(Get-DhcpServerv4Scope -ComputerName '%s' | %s)\n"
            % (_safe_host(server), _SELECT_SCOPE)
        )
        return scopes_from_rows(_rows(self.run(script)))

    def list_leases(self, server: str, scope_id: str) -> list[DhcpLease]:
        script = _PREAMBLE + (
            "ConvertTo-Json -Compress -Depth 3 -InputObject "
            "@(Get-DhcpServerv4Lease -ComputerName '%s' -ScopeId '%s' | %s)\n"
            % (_safe_host(server), _safe_ip(scope_id), _SELECT_LEASE)
        )
        return leases_from_rows(_rows(self.run(script)), server=server,
                                scope_id=scope_id)

    def find_lease(self, server: str, ip: str) -> DhcpLease | None:
        """Аренда одного адреса — для проверки «что там сейчас»."""
        script = _PREAMBLE + (
            "ConvertTo-Json -Compress -Depth 3 -InputObject "
            "@(Get-DhcpServerv4Lease -ComputerName '%s' -IPAddress '%s' | %s)\n"
            % (_safe_host(server), _safe_ip(ip), _SELECT_LEASE)
        )
        leases = leases_from_rows(_rows(self.run(script)), server=server)
        return leases[0] if leases else None


def _short_ps_error(text: str) -> str:
    """Оставить от простыни PowerShell первую содержательную строку."""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("+") and "CategoryInfo" not in stripped:
            return stripped[:400]
    return (text or "").strip()[:400]


def _import_winrm():
    try:
        import winrm
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise DhcpError(
            "Не установлена библиотека pywinrm. Установите её в окружении "
            "портала: pip install pywinrm"
        ) from exc
    return winrm
