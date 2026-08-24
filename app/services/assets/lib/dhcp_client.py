"""Чтение аренд Windows DHCP через WinRM.

Почему именно так. У службы DHCP от Microsoft нет ни LDAP-интерфейса, ни
HTTP-API: единственный поддерживаемый способ получить аренды — модуль
PowerShell ``DhcpServer``. Поэтому портал открывает сессию WinRM и выполняет
там команды чтения.

Только чтение. До сервера уходят исключительно команды из списка
:data:`ALLOWED_CMDLETS`; всё остальное отбраковывается :func:`_guard` ещё до
отправки. Проверяется весь текст сценария, а не начала строк, поэтому спрятать
запись внутри присваивания (``$x = Remove-Item …``) не получится.

Почему результат едет в base64. WinRM открывает оболочку с кодовой страницей,
и pywinrm по умолчанию просит 437 — американскую, без кириллицы. Windows
приводит вывод к ней **до отправки**, и русские названия областей DHCP
приезжали как ``?????``: символы уничтожены на источнике, восстанавливать
нечего. Мы и просим UTF-8 (65001), и дополнительно упаковываем ответ в base64
— он состоит из латиницы и цифр, поэтому проходит через любую кодовую
страницу без потерь. Одной настройки мало: кодовую страницу может урезать
политика на стороне Windows, а base64 не зависит ни от чего.

Зачем нужен обратный DNS, которого нет. В этом домене PTR-записи заведены
только для серверов, у рабочих станций их нет — проверено на живых адресах.
Значит имя узла по адресу взять больше неоткуда: аренда DHCP остаётся
единственным источником связки «адрес — имя — MAC».
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime

from .ipaddr import normalize_mac, parse_ip

#: Команды, которым разрешено уходить на сервер. Все — чтение.
ALLOWED_CMDLETS = frozenset({
    "Import-Module",
    "ConvertTo-Json",
    "Select-Object",
    "Get-DhcpServerInDC",
    "Get-DhcpServerv4Scope",
    "Get-DhcpServerv4Lease",
})

#: UTF-8. Кодовая страница по умолчанию у pywinrm — 437, и кириллица в ней
#: превращается в «?» ещё на стороне Windows.
CODEPAGE_UTF8 = 65001

#: Строки в одинарных кавычках вырезаются перед проверкой: внутри них лежат
#: имена серверов вида ``dc1-sovet61``, и дефис в них — не команда.
_QUOTED = re.compile(r"'[^']*'")
_CMDLET = re.compile(r"\b[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*\b")

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
    """Убедиться, что в сценарии нет ничего, кроме разрешённого чтения.

    Проверяется весь текст, а не начала строк: команду записи можно спрятать
    в присваивании, в конвейере или за точкой с запятой, и построчная проверка
    её бы пропустила.
    """
    naked = _QUOTED.sub("''", script)
    used = set(_CMDLET.findall(naked))
    forbidden = sorted(used - ALLOWED_CMDLETS)
    if forbidden:
        raise DhcpError(
            "Внутренняя ошибка: сервис пытается выполнить на DHCP-сервере "
            "команду, которой нет в списке разрешённого чтения (%s). "
            "Запрос не отправлен." % ", ".join(forbidden)
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


def decode_payload(raw: str) -> str:
    """Развернуть ответ сервера: base64 → UTF-8.

    Если пришло не base64, значит PowerShell напечатал ошибку открытым
    текстом — показываем её оператору, а не «неверный формат».
    """
    text = "".join((raw or "").split())
    if not text:
        return ""
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DhcpError(
            "DHCP-сервер вернул не тот ответ, которого ждали. Обычно так "
            "выглядит ошибка PowerShell: %s" % (raw or "")[:300]
        ) from exc
    return data.decode("utf-8", "replace")


def _rows(payload: str) -> list[dict]:
    """Разобрать JSON в список словарей.

    Пустой вывод — это не ошибка, а «ничего не нашлось»: команда, не вернувшая
    объектов, печатает пустую строку.
    """
    text = (payload or "").strip()
    if not text or text == "null":
        return []
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise DhcpError(
            "DHCP-сервер вернул неразборчивый ответ. Начало: %s" % text[:300]
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

_SELECT_SERVER = (
    "Select-Object DnsName,"
    "@{n='IPAddress';e={$_.IPAddress.IPAddressToString}}"
)


def build_script(pipeline: str) -> str:
    """Собрать сценарий чтения: результат уходит в base64.

    ``ConvertTo-Json`` вызывается с ``-InputObject``, а не через конвейер:
    конвейер разворачивает массив из одного элемента, и ответ на «нашлась
    ровно одна аренда» приезжал бы объектом вместо списка.

    Кавычки вокруг ``$json`` не лишние: если команда не вернула объектов,
    ``ConvertTo-Json`` даёт ``$null``, а ``GetBytes($null)`` — отказ. Так
    получается пустая строка, которую разбор понимает как «ничего нет».
    """
    return (
        "$ErrorActionPreference='Stop'\n"
        "Import-Module DhcpServer\n"
        "$rows = @(%s)\n"
        "$json = ConvertTo-Json -Compress -Depth 3 -InputObject $rows\n"
        "$bytes = [Text.Encoding]::UTF8.GetBytes(\"$json\")\n"
        "[Convert]::ToBase64String($bytes)\n" % pipeline
    )


class DhcpClient:
    """Сессия WinRM к серверу, где есть модуль DhcpServer.

    Все команды выполняются на этом одном сервере; к чужим площадкам он
    обращается сам, через ``-ComputerName``. Портал наружу больше никуда не
    ходит.
    """

    def __init__(self, config: DhcpConfig) -> None:
        self.config = config
        self._proto = None

    def _protocol(self):
        if self._proto is not None:
            return self._proto
        if not self.config.is_configured:
            raise DhcpError(
                "Подключение к DHCP не настроено: укажите сервер, учётную "
                "запись и пароль в настройках сервиса."
            )
        protocol_module = _import_winrm()
        scheme = "https" if self.config.use_ssl else "http"
        endpoint = "%s://%s:%s/wsman" % (
            scheme, _safe_host(self.config.host), int(self.config.port)
        )
        self._proto = protocol_module.Protocol(
            endpoint=endpoint,
            transport="ntlm",
            username=self.config.username,
            password=self.config.password,
            server_cert_validation="ignore",
            read_timeout_sec=self.config.timeout + 10,
            operation_timeout_sec=self.config.timeout,
        )
        return self._proto

    def close(self) -> None:
        self._proto = None

    def __enter__(self) -> "DhcpClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def run(self, script: str) -> str:
        """Выполнить сценарий чтения и вернуть его вывод, уже раскодированный.

        Оболочка открывается напрямую через ``Protocol``, а не через
        ``Session``: у ``Session.run_ps`` кодовая страница зашита в умолчание
        (437), и задать UTF-8 через него нельзя.
        """
        _guard(script)
        proto = self._protocol()
        encoded = base64.b64encode(script.encode("utf_16_le")).decode("ascii")
        command = ("powershell -NoProfile -NonInteractive -EncodedCommand %s"
                   % encoded)

        try:
            shell_id = proto.open_shell(codepage=CODEPAGE_UTF8)
        except Exception as exc:  # noqa: BLE001 — winrm бросает разное
            raise DhcpError(
                "Не удалось открыть сессию WinRM на %s: %s. Проверьте, что "
                "WinRM включён и учётной записи разрешено подключение."
                % (self.config.host, exc)
            ) from exc

        try:
            command_id = proto.run_command(shell_id, command)
            try:
                std_out, std_err, status = proto.get_command_output(
                    shell_id, command_id
                )
            finally:
                proto.cleanup_command(shell_id, command_id)
        except DhcpError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise DhcpError(
                "Не удалось выполнить запрос на %s: %s"
                % (self.config.host, exc)
            ) from exc
        finally:
            try:
                proto.close_shell(shell_id)
            except Exception:  # noqa: BLE001 — оболочка закроется по таймауту
                pass

        if status != 0:
            error = _text(std_err) or _text(std_out)
            raise DhcpError(
                "DHCP-сервер отклонил запрос: %s"
                % (_short_ps_error(error) or "код %s" % status)
            )
        return decode_payload(_text(std_out))

    # --- операции чтения --------------------------------------------------

    def list_servers(self) -> list[DhcpServer]:
        """Все авторизованные в домене DHCP-серверы.

        Список ведёт сама AD, поэтому он всегда актуален. Но опросить каждый
        из них удаётся не всегда: между площадками стоят межсетевые экраны, и
        обращение к дальнему серверу отваливается с «Failed to get version».
        """
        script = build_script(
            "Get-DhcpServerInDC | %s" % _SELECT_SERVER
        )
        return servers_from_rows(_rows(self.run(script)))

    def list_scopes(self, server: str) -> list[DhcpScopeInfo]:
        script = build_script(
            "Get-DhcpServerv4Scope -ComputerName '%s' | %s"
            % (_safe_host(server), _SELECT_SCOPE)
        )
        return scopes_from_rows(_rows(self.run(script)))

    def list_leases(self, server: str, scope_id: str) -> list[DhcpLease]:
        script = build_script(
            "Get-DhcpServerv4Lease -ComputerName '%s' -ScopeId '%s' | %s"
            % (_safe_host(server), _safe_ip(scope_id), _SELECT_LEASE)
        )
        return leases_from_rows(_rows(self.run(script)), server=server,
                                scope_id=scope_id)

    def find_lease(self, server: str, ip: str) -> DhcpLease | None:
        """Аренда одного адреса — для проверки «что там сейчас»."""
        script = build_script(
            "Get-DhcpServerv4Lease -ComputerName '%s' -IPAddress '%s' | %s"
            % (_safe_host(server), _safe_ip(ip), _SELECT_LEASE)
        )
        leases = leases_from_rows(_rows(self.run(script)), server=server)
        return leases[0] if leases else None


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _short_ps_error(text: str) -> str:
    """Оставить от простыни PowerShell первую содержательную строку."""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("+") and "CategoryInfo" not in stripped:
            return stripped[:400]
    return (text or "").strip()[:400]


def _import_winrm():
    try:
        from winrm import protocol
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise DhcpError(
            "Не установлена библиотека pywinrm. Установите её в окружении "
            "портала: pip install pywinrm"
        ) from exc
    return protocol
