"""Клиент MaxPatrol SIEM: по домену находит конечные хосты организации.

Зачем нужен. SkyDNS показывает, что из организации ходили на вредоносный
домен, но не показывает, кто именно: в облако прилетает адрес шлюза. Ответ
знает SIEM — в нём лежат события DNS/прокси, где рядом с доменом есть
конечный хост. Клиент повторяет ровно тот запрос, который оператор делает
руками в интерфейсе SIEM:

    фильтр:       datafield1 = "<домен>" or datafield3 = "<домен>"
    группировка:  src.ip

и возвращает значения группировки (обычно IP-адреса) со счётчиком событий.

Реализация — только на стандартной библиотеке, как и vt_client: приложение
должно ставиться в изолированной сети без доступа к PyPI.

Поддерживаются два способа аутентификации, оба встречаются в инсталляциях
MaxPatrol SIEM:

  * ``session`` — форма ``/ui/login`` на порту Core (3334) с последующим
    OIDC form-post редиректом; авторизация живёт в cookie;
  * ``token``   — OAuth2 password grant на ``/connect/token`` порта Core;
    авторизация передаётся заголовком ``Authorization: Bearer``.

Порядок вызовов и формат тела запроса повторяют официальную обёртку
``mpsiem_api`` (она построена на ``requests``, поэтому редиректы там идут
автоматически — здесь используется штатный обработчик редиректов urllib
с общей банкой cookie, что даёт то же поведение).
"""
from __future__ import annotations

import html
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from http.cookiejar import CookieJar

# Порт компонента Core, на котором висят форма входа и выдача токенов.
CORE_PORT = 3334

# Пути API MaxPatrol SIEM.
PATH_UI_LOGIN = "/ui/login"
PATH_LOGIN_FORM = "/account/login"
LOGIN_FORM_QUERY = "returnUrl=/"
PATH_TOKEN = "/connect/token"
PATH_SYSTEM_INFO = "/api/deployment_configuration/v1/system_info"
PATH_EVENTS = "/api/events/v2/events"

# Типы аутентификации формы /ui/login.
AUTH_TYPE_LOCAL = 0
AUTH_TYPE_LDAP = 1

# Скоупы, которые запрашивает веб-интерфейс SIEM при password grant.
TOKEN_SCOPE = "authorization offline_access mpx.api ptkb.api"
DEFAULT_CLIENT_ID = "mpx"

# Полный набор полей таксономии MaxPatrol SIEM (тот же список, что подставляет
# официальная обёртка mpsiem_api). Нужен диагностике: SIEM возвращает ровно те
# поля, которые перечислены в select, поэтому увидеть, где в событии лежит
# адрес конечного хоста, можно только запросив всё сразу.
TAXONOMY_FIELDS = (
    "action", "agent_id", "aggregation_name", "asset_ids",
    "assigned_dst_host", "assigned_dst_ip", "assigned_dst_port",
    "assigned_src_host", "assigned_src_ip", "assigned_src_port",
    "category.generic", "category.high", "category.low", "chain_id",
    "correlation_name", "correlation_type", "count", "count.bytes",
    "count.bytes_in", "count.bytes_out", "count.packets",
    "count.packets_in", "count.packets_out", "count.subevents",
    "datafield1", "datafield10", "datafield2", "datafield3", "datafield4",
    "datafield5", "datafield6", "datafield7", "datafield8", "datafield9",
    "detect", "direction", "dst.asset", "dst.fqdn", "dst.geo.asn",
    "dst.geo.city", "dst.geo.country", "dst.geo.org", "dst.host",
    "dst.hostname", "dst.ip", "dst.mac", "dst.port", "duration",
    "event_src.asset", "event_src.category", "event_src.fqdn",
    "event_src.host", "event_src.hostname", "event_src.id", "event_src.ip",
    "event_src.subsys", "event_src.title", "event_src.vendor", "event_type",
    "external_link", "generator", "generator.type", "generator.version",
    "historical", "id", "importance", "incorrect_time", "input_id",
    "interface", "job_id", "logon_auth_method", "logon_service",
    "logon_type", "mime", "msgid", "nas_fqdn", "nas_ip", "normalized",
    "object", "object.account.contact", "object.account.dn",
    "object.account.domain", "object.account.fullname",
    "object.account.group", "object.account.id", "object.account.name",
    "object.account.privileges", "object.account.session_id",
    "object.domain", "object.fullpath", "object.group", "object.hash",
    "object.id", "object.name", "object.path", "object.process.cmdline",
    "object.process.cwd", "object.process.fullpath", "object.process.guid",
    "object.process.hash", "object.process.id", "object.process.meta",
    "object.process.name", "object.process.original_name",
    "object.process.parent.cmdline", "object.process.parent.fullpath",
    "object.process.parent.guid", "object.process.parent.hash",
    "object.process.parent.id", "object.process.parent.name",
    "object.process.parent.path", "object.process.path",
    "object.process.version", "object.property", "object.query",
    "object.state", "object.type", "object.value", "object.vendor",
    "object.version", "original_time", "protocol", "protocol.layer7",
    "reason", "recv_asset", "recv_host", "recv_ipv4", "recv_ipv6",
    "recv_time", "remote", "scope_id", "siem_id", "site_address",
    "site_alias", "site_id", "site_name", "src.asset", "src.fqdn",
    "src.geo.asn", "src.geo.city", "src.geo.country", "src.geo.org",
    "src.host", "src.hostname", "src.ip", "src.mac", "src.port",
    "start_time", "status", "subevents", "subject",
    "subject.account.contact", "subject.account.dn",
    "subject.account.domain", "subject.account.fullname",
    "subject.account.group", "subject.account.id", "subject.account.name",
    "subject.account.privileges", "subject.account.session_id",
    "subject.domain", "subject.group", "subject.id", "subject.name",
    "subject.privileges", "subject.process.cmdline", "subject.process.cwd",
    "subject.process.fullpath", "subject.process.guid",
    "subject.process.hash", "subject.process.id", "subject.process.meta",
    "subject.process.name", "subject.process.original_name",
    "subject.process.parent.cmdline", "subject.process.parent.fullpath",
    "subject.process.parent.guid", "subject.process.parent.hash",
    "subject.process.parent.id", "subject.process.parent.name",
    "subject.process.parent.path", "subject.process.path",
    "subject.process.version", "subject.state", "subject.type",
    "subject.version", "tag", "task_id", "taxonomy_version", "tcp_flag",
    "tenant_id", "text", "time", "type", "uuid"
)

#: Сколько событий просить за один запрос. Больше тысячи SIEM отдаёт неохотно,
#: а страницами дочитывается сколько нужно.
PAGE_SIZE = 1000

USER_AGENT = "rpz-portal/1.0"


class SiemError(Exception):
    """Ошибка обращения к SIEM, пригодная для показа оператору."""


class SiemAuthError(SiemError):
    """Не удалось аутентифицироваться (неверная УЗ, истёк пароль)."""


@dataclass
class SiemConfig:
    """Параметры подключения к SIEM (берутся из настроек приложения)."""

    base_url: str = ""
    auth_mode: str = "session"          # session | token
    auth_type: str = "local"            # local | ldap (только для session)
    username: str = ""
    password: str = ""
    client_id: str = DEFAULT_CLIENT_ID
    client_secret: str = ""
    verify_ssl: bool = False
    # Сгруппированный запрос за несколько суток SIEM считает не мгновенно,
    # поэтому 30 секунд по умолчанию было мало: обрывалось на полпути.
    timeout: int = 120
    # Предел событий на домен: защита от имени, по которому в SIEM
    # миллион записей. Страницами дочитывается всё до этого предела.
    limit: int = 20000

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.username and self.password)


@dataclass
class HostHit:
    """Одна строка сгруппированного ответа SIEM."""

    address: str
    events_count: int = 0
    hostname: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class SearchResult:
    hosts: list[HostHit] = field(default_factory=list)
    total_count: int = 0
    query_filter: str = ""
    #: Дочитать до конца не удалось — часть хостов осталась за кадром.
    truncated: bool = False
    #: Сколько событий фактически прочитано (может быть меньше total_count).
    events_read: int = 0


def _normalize_base(base_url: str) -> str:
    """Привести адрес SIEM к виду ``https://host`` без хвостового слэша."""
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise SiemError("Не задан адрес MaxPatrol SIEM — укажите его в настройках.")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base


#: Порты, которые в адресе ничего не значат: это порт по умолчанию для схемы.
DEFAULT_PORTS = {"http": 80, "https": 443}


def _core_url(base_url: str, path: str) -> str:
    """URL компонента Core: тот же хост, но порт 3334.

    Если в настройках порт указали явно, он считается осознанным выбором
    и не подменяется. Исключение — 443 и 80: их браузер показывает в адресной
    строке сам, и скопированный оттуда адрес не означает, что вход в Core
    надо искать там же.
    """
    parts = urllib.parse.urlsplit(_normalize_base(base_url))
    port = parts.port
    if port and port != DEFAULT_PORTS.get(parts.scheme):
        netloc = parts.netloc
    else:
        netloc = f"{parts.hostname}:{CORE_PORT}"
    return urllib.parse.urlunsplit((parts.scheme, netloc, path, "", ""))


def _api_url(base_url: str, path: str, query: str = "") -> str:
    parts = urllib.parse.urlsplit(_normalize_base(base_url))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def _ssl_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        # В большинстве инсталляций у SIEM самоподписанный сертификат.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _to_unix_seconds(moment: datetime) -> int:
    """SIEM ждёт границы периода в секундах Unix, а не в миллисекундах."""
    return int(moment.timestamp())


class SiemClient:
    """Сессия работы с SIEM. Создаётся на одну серию запросов и закрывается."""

    def __init__(self, config: SiemConfig) -> None:
        self.config = config
        self._cookies = CookieJar()
        self._token = ""
        # Редиректы идут своим чередом: вход в SIEM — это цепочка OIDC
        # (/account/login → /connect/authorize на Core → возврат обратно),
        # и пройти её надо целиком, попутно собирая cookie.
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_ssl_context(config.verify_ssl)),
            urllib.request.HTTPCookieProcessor(self._cookies),
        )

    # --- низкий уровень ---------------------------------------------------

    def _request(
        self,
        url: str,
        data: bytes | None = None,
        headers: dict | None = None,
        method: str | None = None,
        accept: str = "application/json",
    ):
        base_headers = {"User-Agent": USER_AGENT, "Accept": accept}
        if self._token:
            base_headers["Authorization"] = f"Bearer {self._token}"
        base_headers.update(headers or {})

        request = urllib.request.Request(
            url, data=data, headers=base_headers, method=method
        )
        try:
            return self._opener.open(request, timeout=self.config.timeout)
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise SiemError(f"Не удалось связаться с SIEM ({url}): {exc}") from exc

    def _read_json(self, response) -> dict:
        raw = response.read().decode("utf-8", errors="replace")
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SiemError("SIEM вернул ответ, который не удалось разобрать.") from exc

    # --- аутентификация ---------------------------------------------------

    def login(self) -> None:
        if not self.config.is_configured:
            raise SiemError(
                "MaxPatrol SIEM не настроен: укажите адрес, логин и пароль "
                "в разделе «Настройки»."
            )
        if self.config.auth_mode == "token":
            self._login_token()
        else:
            self._login_session()

    def _login_token(self) -> None:
        """OAuth2 password grant на порту Core."""
        payload = urllib.parse.urlencode({
            "client_id": self.config.client_id or DEFAULT_CLIENT_ID,
            "client_secret": self.config.client_secret,
            "grant_type": "password",
            "username": self.config.username,
            "password": self.config.password,
            "response_type": "code id_token",
            "scope": TOKEN_SCOPE,
        }).encode()

        try:
            response = self._request(
                _core_url(self.config.base_url, PATH_TOKEN),
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            if exc.code in (400, 401):
                raise SiemAuthError(
                    "SIEM отклонил учётные данные при получении токена "
                    f"({exc.code}). {detail}"
                ) from exc
            raise SiemError(f"Ошибка получения токена SIEM ({exc.code}). {detail}") from exc

        payload = self._read_json(response)
        token = payload.get("access_token") or ""
        if not token:
            raise SiemAuthError("SIEM не вернул access_token.")
        self._token = token

    def _login_session(self) -> None:
        """Вход через форму /ui/login с последующим OIDC form-post."""
        auth_type = (
            AUTH_TYPE_LDAP if self.config.auth_type == "ldap" else AUTH_TYPE_LOCAL
        )
        body = json.dumps({
            "authType": auth_type,
            "username": self.config.username,
            "password": self.config.password,
            "newPassword": None,
        }).encode()

        try:
            response = self._request(
                _core_url(self.config.base_url, PATH_UI_LOGIN),
                data=body,
                headers={"Content-Type": "application/json;charset=UTF-8"},
            )
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise SiemAuthError(
                f"SIEM отклонил вход ({exc.code}). {detail}"
            ) from exc

        payload = self._read_json(response)
        # При неверном пароле Core отвечает 200 с полем message.
        if payload.get("message"):
            raise SiemAuthError(f"SIEM отклонил вход: {payload['message']}")

        # Забираем HTML-форму авторизации и отправляем её — так веб-интерфейс
        # обменивает сессию Core на cookie основного портала SIEM. Страница
        # отдаётся в HTML, поэтому Accept: application/json тут неуместен.
        form_url = _api_url(self.config.base_url, PATH_LOGIN_FORM, LOGIN_FORM_QUERY)
        try:
            form_html = self._request(
                form_url, accept="text/html,application/xhtml+xml,*/*"
            ).read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise SiemAuthError(
                f"Форма авторизации SIEM недоступна ({exc.code})."
            ) from exc

        action, fields = self._parse_login_form(form_html)
        if action:
            try:
                self._request(
                    urllib.parse.urljoin(form_url, action),
                    data=urllib.parse.urlencode(fields).encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    accept="text/html,application/xhtml+xml,*/*",
                )
            except urllib.error.HTTPError as exc:
                raise SiemAuthError(
                    f"SIEM отклонил обмен сессии ({exc.code})."
                ) from exc

        # Контрольный запрос: если сессия не поднялась, дальше нет смысла.
        try:
            check = self._request(_api_url(self.config.base_url, PATH_SYSTEM_INFO))
        except urllib.error.HTTPError as exc:
            raise SiemAuthError(
                f"Сессия SIEM не установлена: {PATH_SYSTEM_INFO} вернул {exc.code}."
            ) from exc
        if check.status != 200:
            raise SiemAuthError(
                f"Сессия SIEM не установлена (код {check.status})."
            )

    @staticmethod
    def _parse_login_form(page: str) -> tuple[str, dict]:
        """Достать action и скрытые поля из HTML-формы авторизации."""
        action_match = re.search(r"action=['\"]([^'\"]*)['\"]", page)
        fields = {
            match.group(1): html.unescape(match.group(2))
            for match in re.finditer(
                r"name=['\"]([^'\"]*)['\"]\s+value=['\"]([^'\"]*)['\"]", page
            )
        }
        return (action_match.group(1) if action_match else ""), fields

    # --- поиск ------------------------------------------------------------

    def _events(self, body: dict, limit: int, offset: int = 0,
                token: str = "") -> dict:
        """Отправить запрос событий и вернуть разобранный ответ."""
        params = {"limit": limit, "offset": offset}
        if token:
            # Токен выдаётся первой страницей и закрепляет выборку: без него
            # следующие страницы считались бы по изменившемуся набору событий.
            params["token"] = token
        url = _api_url(
            self.config.base_url, PATH_EVENTS, urllib.parse.urlencode(params)
        )
        try:
            response = self._request(
                url,
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json;charset=UTF-8"},
            )
        except urllib.error.HTTPError as exc:
            detail = _extract_error(exc.read().decode("utf-8", errors="replace"))
            if exc.code in (401, 403):
                raise SiemAuthError(
                    f"SIEM отклонил запрос событий ({exc.code}). "
                    "Проверьте права учётной записи. " + detail
                ) from exc
            raise SiemError(
                f"SIEM вернул ошибку {exc.code} на запрос событий. {detail}"
            ) from exc

        return self._read_json(response)

    def search_hosts(
        self,
        domain: str,
        time_from: datetime,
        time_to: datetime,
        filter_template: str,
        group_field: str,
        limit: int | None = None,
    ) -> SearchResult:
        """Найти конечные хосты, обращавшиеся к домену.

        Повторяет ручной запрос оператора: фильтр по домену + группировка по
        полю ``group_field`` (по умолчанию ``src.ip``). В настройке можно
        перечислить несколько полей через запятую — см. :func:`_group_fields`.
        """
        domain = (domain or "").strip().lower()
        if not domain:
            raise SiemError("Пустой домен для поиска в SIEM.")

        fields = _group_fields(group_field)
        query_filter = _render_filter(filter_template, domain)
        cap = limit or self.config.limit
        body = _build_group_query(
            query_filter=query_filter,
            group_field=fields,
            time_from=time_from,
            time_to=time_to,
            select=_select_for(fields),
            # Группировку не просим намеренно, см. _build_group_query.
            group_by=[],
        )

        rows, total, truncated = self._read_all_events(body, cap)
        return SearchResult(
            hosts=_parse_group_rows({"events": rows}, fields),
            total_count=total,
            query_filter=query_filter,
            truncated=truncated,
            events_read=len(rows),
        )

    def _read_all_events(self, body: dict, cap: int) -> tuple[list, int, bool]:
        """Вычитать события страницами, пока не кончатся или не упрёмся в предел.

        За один ответ SIEM отдаёт ограниченное число строк, а хостов в
        организации может быть куда больше, чем помещается в одну страницу:
        адреса рабочих станций распределены по выборке неравномерно, и первая
        тысяча событий запросто окажется трафиком одного шумного узла.
        Поэтому страницы дочитываются до ``totalCount``.

        Предел ``cap`` — защита от домена, по которому в SIEM миллион
        событий: лучше честно сказать, что взяли не всё, чем висеть час.
        """
        collected: list = []
        total = 0
        token = ""
        page = dict(body)

        while len(collected) < cap:
            size = min(PAGE_SIZE, cap - len(collected))
            payload = self._events(page, size, offset=len(collected), token=token)
            rows = _response_rows(payload)
            total = int(payload.get("totalCount") or total)
            token = str(payload.get("token") or token)
            collected.extend(rows)

            if not rows or len(collected) >= total:
                break
            # Со второй страницы выборку закрепляем токеном, а верхнюю
            # границу периода снимаем: события, приехавшие уже во время
            # чтения, иначе сдвигали бы нумерацию страниц.
            page = dict(body, timeTo=None)

        return collected, total, len(collected) < total

    def probe(
        self,
        domain: str,
        time_from: datetime,
        time_to: datetime,
        filter_template: str,
        group_field: str,
        limit: int = 200,
    ) -> dict:
        """Диагностика: какие поля events на самом деле заполнены.

        Когда поиск возвращает ноль хостов, вопрос всегда один: событий не
        нашлось вовсе или они нашлись, но адрес конечного хоста лежит не в
        том поле, которое мы читаем.

        Ключевая деталь: SIEM возвращает ровно те поля, которые перечислены
        в ``select``. Спрашивая только настроенное поле, увидеть остальные
        невозможно, поэтому здесь запрашивается вся таксономия, а группировка
        не запрашивается вовсе — нужны сырые события, чтобы разглядеть, где
        в них адрес.

        Строк берём заметно больше, чем нужно для показа: адреса рабочих
        станций распределены по выборке неравномерно, и по двум десяткам
        событий легко решить, что хост всего один.
        """
        fields = _group_fields(group_field)
        query_filter = _render_filter(filter_template, (domain or "").strip().lower())
        body = _build_group_query(
            query_filter=query_filter, group_field=fields,
            time_from=time_from, time_to=time_to,
            select=list(TAXONOMY_FIELDS), group_by=[],
        )
        payload = self._events(body, limit)
        rows = _response_rows(payload)

        # В показанном запросе select заменяем меткой: две сотни имён полей
        # заслонили бы то, ради чего на него смотрят, — фильтр и период.
        shown = json.loads(json.dumps(body))
        shown["filter"]["select"] = [f"<вся таксономия: {len(TAXONOMY_FIELDS)} полей>"]

        return {
            "request": shown,
            "filter": query_filter,
            "group_fields": fields,
            "total_count": payload.get("totalCount"),
            "rows_returned": len(rows),
            "row_keys": sorted(rows[0].keys()) if rows and isinstance(rows[0], dict)
                        else [],
            "filled": _filled_fields(rows),
            "suggested": _address_candidates(rows, fields, query_filter, domain),
            "rows": rows[:3],
            "parsed": [
                {"address": h.address, "events": h.events_count}
                for h in _parse_group_rows(payload, fields)
            ][:20],
        }

    def close(self) -> None:
        self._opener.close()

    def __enter__(self) -> "SiemClient":
        self.login()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _render_filter(template: str, domain: str) -> str:
    """Подставить домен в шаблон фильтра.

    В шаблоне используется плейсхолдер ``{domain}``. Кавычки в домене
    экранируются — фильтр уходит в SIEM внутри JSON-строки.
    """
    safe = domain.replace("\\", "").replace('"', "")
    if "{domain}" not in template:
        # Шаблон без плейсхолдера считаем готовым фильтром по этому домену.
        return template
    return template.replace("{domain}", safe)


def _group_fields(group_field) -> list[str]:
    """Разобрать настройку поля группировки в список полей.

    Конечный хост в разных источниках событий лежит в разных полях: где-то
    это ``src.ip``, где-то ``src.host``, а в событиях прокси — ``dst.host``.
    Поэтому в настройке разрешено перечислить несколько через запятую:
    группируем по всем, а адресом считаем первое непустое значение.
    """
    if isinstance(group_field, (list, tuple)):
        raw = list(group_field)
    else:
        raw = str(group_field or "").replace(";", ",").split(",")
    fields = [item.strip() for item in raw if item and item.strip()]
    return fields or ["src.ip"]


#: Поля таксономии, в которых вообще может лежать адрес узла. Используются
#: двояко: их запрашивает поиск (сверх настроенных) и по ним диагностика
#: узнаёт «адресные» поля, даже когда значение не похоже на IP.
KNOWN_ADDRESS_FIELDS = (
    "src.ip", "src.host", "src.hostname", "src.fqdn",
    "dst.ip", "dst.host", "dst.hostname", "dst.fqdn",
    "assigned_src_ip", "assigned_src_host",
    "assigned_dst_ip", "assigned_dst_host",
    "event_src.host", "event_src.ip", "event_src.fqdn", "event_src.hostname",
    "recv_ipv4", "recv_ipv6", "recv_host", "nas_ip", "nas_fqdn",
)


def _select_for(fields: list[str]) -> list[str]:
    """Какие поля просить у SIEM при обычном поиске.

    Настроенные поля плюс остальные адресные: ``select`` — это проекция, на
    отбор строк он не влияет, а лишний десяток колонок дешевле, чем ещё один
    заход к оператору с вопросом «а что у вас в событии заполнено».
    Всю таксономию (195 полей) тянуть при этом незачем: на сотнях доменов
    это уже мегабайты ответа.
    """
    ordered = list(fields)
    for name in KNOWN_ADDRESS_FIELDS + ("time", "action"):
        if name not in ordered:
            ordered.append(name)
    return ordered


def _build_group_query(
    query_filter: str,
    group_field,
    time_from: datetime,
    time_to: datetime,
    select: list[str] | None = None,
    group_by: list[str] | None = None,
) -> dict:
    """Тело запроса ``/api/events/v2/events``.

    Группировку мы у SIEM не просим, и это осознанно. Один DNS-запрос
    порождает пару событий: ``action=receive`` — сервер принял запрос от
    рабочей станции (её адрес в ``src.ip``), и ``action=send`` — сервер
    переслал запрос вышестоящему DNS (там ``src.ip`` пуст, а в ``dst.ip``
    стоит внешний резолвер).

    С ``groupBy`` наблюдаемая инсталляция возвращала по одной строке на
    отметку времени и выбирала из такой пары представителя без ``src.ip`` —
    поиск честно находил события и не находил ни одного адреса. Без
    группировки приходят все события, а сведение по адресам делается на
    нашей стороне (см. :func:`_parse_group_rows`): события с пустым полем
    просто пропускаются.
    """
    fields = _group_fields(group_field)
    grouping = fields if group_by is None else group_by
    return {
        "filter": {
            "select": select if select is not None else fields + ["time"],
            "where": query_filter,
            "orderBy": [{"field": "time", "sortOrder": "descending"}],
            "groupBy": grouping,
            "aggregateBy": (
                [{"function": "COUNT", "field": fields[0], "unique": False}]
                if grouping else []
            ),
            "distributeBy": [],
            "top": None,
            "aliases": {},
        },
        "groupValues": [],
        "timeFrom": _to_unix_seconds(time_from),
        "timeTo": _to_unix_seconds(time_to),
    }


def _extract_error(raw: str) -> str:
    """Вытащить человекочитаемое сообщение из тела ошибки SIEM."""
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw[:300]
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            message = (first.get("error") or {}).get("message")
            if message:
                return str(message)
    return str(payload.get("message") or raw[:300])


def _response_rows(payload: dict) -> list:
    """Строки ответа SIEM: в разных версиях это ``events`` либо ``rows``."""
    rows = payload.get("events")
    if not isinstance(rows, list):
        rows = payload.get("rows") if isinstance(payload.get("rows"), list) else []
    return rows


def _parse_group_rows(payload: dict, group_field) -> list[HostHit]:
    """Разобрать сгруппированный ответ SIEM в список хостов.

    Формат сгруппированного ответа отличается между версиями SIEM, поэтому
    разбор намеренно терпимый: ищем значение поля группировки и счётчик в
    нескольких возможных местах строки ответа.
    """
    fields = _group_fields(group_field)
    rows = _response_rows(payload)

    hits: dict[str, HostHit] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = _row_value(row, fields)
        if not address:
            continue
        count = _row_count(row)
        hit = hits.get(address)
        if hit is None:
            hits[address] = HostHit(address=address, events_count=count)
        else:
            hit.events_count += count

    return sorted(hits.values(), key=lambda h: (-h.events_count, h.address))


def _row_value(row: dict, fields: list[str]) -> str:
    """Значение поля группировки в строке ответа.

    Полей может быть несколько: берём первое, у которого есть значение —
    события одного и того же обращения приезжают из разных источников, и
    адрес конечного хоста заполнен не везде одинаково.
    """
    # 1. Поле лежит прямо в строке (обычный случай).
    for name in fields:
        value = row.get(name)
        if value not in (None, "", "null"):
            return str(value).strip()

    # 2. Строка обёрнута: {"fields": {...}} либо {"event": {...}}.
    for key in ("fields", "event", "values"):
        nested = row.get(key)
        if not isinstance(nested, dict):
            continue
        for name in fields:
            if nested.get(name) not in (None, "", "null"):
                return str(nested[name]).strip()

    # 3. Групповой ответ: {"groupValues": ["10.0.0.5"]} или {"key": ...}.
    group_values = row.get("groupValues")
    if isinstance(group_values, list):
        for value in group_values:
            if value not in (None, "", "null"):
                return str(value).strip()
    for key in ("groupValue", "key", "value"):
        if row.get(key):
            return str(row[key]).strip()
    return ""


def _row_count(row: dict) -> int:
    """Счётчик событий в строке сгруппированного ответа."""
    for key in _count_keys(row):
        value = row.get(key)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
        if isinstance(value, list) and value:
            first = value[0]
            if isinstance(first, (int, float)):
                return int(first)
            if isinstance(first, dict):
                for sub in ("value", "count"):
                    if isinstance(first.get(sub), (int, float)):
                        return int(first[sub])
    return 1


#: Поля, которые адресом конечного хоста быть не могут, как бы они ни
#: выглядели: служебные метки события и его собственное время.
_NOT_ADDRESS = {"time", "_meta", "recv_time", "original_time", "start_time",
                "id", "uuid", "siem_id", "input_id", "job_id", "task_id",
                "chain_id", "agent_id", "scope_id", "tenant_id", "site_id"}

#: Похоже на имя узла: без пробелов, с точкой или дефисом внутри.
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,62})$")


def _is_empty(value) -> bool:
    """Пустое значение поля события во всех видах, в которых оно приходит."""
    return value in (None, "", "null", "None", [], {})


def _filled_fields(rows: list) -> list[dict]:
    """Какие поля реально заполнены в найденных событиях.

    Ради этого списка диагностика и существует: он показывает, что у события
    есть на самом деле, вместо того чтобы гадать имя поля по документации.
    Отсортирован по частоте заполнения — сверху то, что есть почти везде.
    """
    counts: dict[str, int] = {}
    samples: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name, value in row.items():
            if name == "_meta" or _is_empty(value):
                continue
            counts[name] = counts.get(name, 0) + 1
            if name not in samples:
                samples[name] = str(value)[:120]
    return [
        {"field": name, "rows": counts[name], "sample": samples[name]}
        for name in sorted(counts, key=lambda n: (-counts[n], n))
    ]


def _as_ip(value):
    """Разобрать значение как IP-адрес; иначе ``None``."""
    import ipaddress

    text = str(value).strip()
    if not text or " " in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _looks_like_address(value: str) -> bool:
    text = str(value).strip()
    if not text or " " in text:
        return False
    if _as_ip(text) is not None:
        return True
    return bool(_HOSTNAME.match(text)) and ("." in text or "-" in text)


def _address_kind(value: str) -> str:
    """Как пометить значение в подсказке.

    Разница между внутренним и внешним адресом здесь решающая: в событиях
    DNS-сервера ``dst.ip`` — это вышестоящий резолвер в интернете, а вовсе
    не рабочая станция организации. Подписав адрес «внешний», подсказка
    удерживает от очевидной, но неверной настройки.
    """
    address = _as_ip(value)
    if address is None:
        return "имя узла"
    if address.is_private or address.is_loopback or address.is_link_local:
        return "внутренний адрес"
    return "внешний адрес"


#: Порядок подсказок: сначала то, что похоже на рабочую станцию.
_KIND_ORDER = {"внутренний адрес": 0, "имя узла": 1, "внешний адрес": 2}


def _address_candidates(rows: list, configured: list[str],
                        query_filter: str = "", domain: str = "") -> list[dict]:
    """Поля, которые могут содержать адрес конечного хоста.

    Оператору не обязательно знать таксономию SIEM наизусть. Поле попадает
    в подсказки, если оно известно как адресное либо его значение — это
    настоящий IP-адрес. Проверки «похоже на имя узла» недостаточно: под неё
    подходит и ``taxonomy_version``, и сам проверяемый домен.

    Отбрасываются: поля из фильтра, поля со значением проверяемого домена
    (``datafield6``, ``object.value`` — там лежит запрошенное имя) и уже
    настроенные.
    """
    skip = set(configured) | _NOT_ADDRESS
    skip |= set(re.findall(r"[A-Za-z_][\w.]*", query_filter or ""))
    needle = (domain or "").strip().lower()

    out = []
    for item in _filled_fields(rows):
        name, sample = item["field"], item["sample"]
        if name in skip:
            continue
        if needle and needle in sample.lower():
            continue
        if name not in KNOWN_ADDRESS_FIELDS and _as_ip(sample) is None:
            continue
        out.append(dict(item, kind=_address_kind(sample)))

    out.sort(key=lambda i: (_KIND_ORDER.get(i["kind"], 3), -i["rows"], i["field"]))
    return out[:12]


def _count_keys(row: dict) -> list[str]:
    """Где в строке может лежать счётчик агрегата.

    Кроме привычных имён, SIEM называет колонку агрегата по самой функции —
    ``COUNT(src.ip)``. Такое имя заранее не угадать, поэтому ищем его прямо
    среди ключей строки.
    """
    known = ["count", "COUNT", "eventsCount", "aggregateValue", "aggregate"]
    generated = [
        key for key in row
        if isinstance(key, str) and key.upper().startswith("COUNT(")
    ]
    return generated + known
