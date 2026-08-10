"""Клиент Proxy Stat API SkyDNS.

Документация: «Proxy Stat API» — прокси-слой к методам stat_api по токену,
выпускаемому под каждого клиента.

    POST https://skydns.ru/cabinet/rest_api/statistics/users/{user_id}/proxy/v2/{method}/
    Authorization: Token XXX
    тело — JSON с параметрами периода и фильтров

Используются четыре метода:

  * ``get_categories_activity`` — справочник категорий с флагом ``is_dangerous``.
    Благодаря ему список «опасных» категорий не нужно вести руками: SkyDNS сам
    говорит, какая категория относится к угрозам.
  * ``get_domains_activity``    — домены с числом запросов, блокировок и
    категориями. Поддерживает фильтр ``cats``, поэтому опасные домены забираются
    одним запросом.
  * ``get_devices_activity``    — устройства (токен + адреса), обращавшиеся к
    заданным доменам. Для устройств с агентом SkyDNS сам знает конечный хост;
    запись с ``token == 0`` — это трафик через шлюз, по ней хост ищется в SIEM.
  * ``get_detailed_activity``   — детализация по минутам: домен, адрес, токен.

Реализация — только на стандартной библиотеке (как vt_client и siem_client):
приложение ставится в изолированной сети без доступа к PyPI.
"""
from __future__ import annotations

import csv
import io
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date

DEFAULT_BASE_URL = "https://skydns.ru"
API_TEMPLATE = "/cabinet/rest_api/statistics/users/{user_id}/proxy/v2/{method}/"
USER_AGENT = "rpz-portal/1.0"

# Методы Proxy Stat API.
M_TOTAL = "get_total_activity"
M_ACTIVITY = "get_activity"
M_CATEGORIES = "get_categories_activity"
M_DOMAINS = "get_domains_activity"
M_DEVICES = "get_devices_activity"
M_DETAILED = "get_detailed_activity"

# Периоды, которые понимает API.
PERIODS = ("today", "yesterday", "week", "month", "range", "date")

# Категории угроз из приложения к инструкции. Используются как запасной
# вариант: основной источник — флаг is_dangerous в ответе API.
DANGEROUS_CATEGORY_IDS = {
    1: "Недавно зарегистрированные домены",
    3: "Malware",
    4: "Phishing & Typosquatting",
    9: "Запаркованные домены",
    12: "Botnets & C2",
    66: "Cryptojacking",
    70: "DGA",
    71: "Ransomware",
    73: "DNS-туннелирование",
}

# Признак «трафик пришёл через шлюз, конечный хост неизвестен».
GATEWAY_TOKEN = 0

# Отчёт формируется асинхронно и отдаётся файлом. Ответ метода — конверт:
#
#   {"task_id": "...", "status": "exists: complete",
#    "message": "https://stch.skydns.ru/data/<id>.json",
#    "updated": "...", "processing_time": 3.31}
#
# Пока отчёт строится, статус другой, а когда готов — в message лежит ссылка
# на JSON с самим отчётом, который нужно скачать отдельным запросом.
# Префикс "exists:" означает, что отчёт уже был построен и взят из кэша.
STATUS_KEYS = ("status", "state", "task_status", "job_status")
# Статус сравнивается по вхождению подстроки: точные значения различаются
# между методами и версиями ("complete", "exists: complete", "error: ...").
STATUS_READY_MARKS = ("complete", "done", "ready", "success", "finish")
STATUS_FAILED_MARKS = ("error", "fail", "cancel", "abort", "denied")

# Ключи, под которыми может лежать сам отчёт, если он пришёл прямо в ответе.
DATA_KEYS = ("result", "results", "data", "report", "rows", "items",
             "objects", "response", "payload")

# Сколько всего ждать готовности отчёта. Обычно он строится за секунды, но
# инструкция допускает до часа на шаг, поэтому предел вынесен в настройки.
REPORT_TIMEOUT = 300
POLL_START = 2
POLL_MAX = 10


class SkydnsError(Exception):
    """Ошибка обращения к SkyDNS, пригодная для показа оператору."""


class SkydnsNotReady(SkydnsError):
    """Отчёт ещё формируется — нужно подождать и спросить снова."""


def _excerpt(payload, limit: int = 400) -> str:
    """Кусок ответа для сообщения об ошибке.

    Без него оператор видит «неожиданный ответ» и не может ничего сделать.
    """
    try:
        text = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(payload)
    return text[:limit] + ("…" if len(text) > limit else "")


def _status_of(payload) -> str:
    """Статус задачи из конверта ответа, если он там есть."""
    if not isinstance(payload, dict):
        return ""
    for key in STATUS_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _status_is(status: str, marks) -> bool:
    """Совпадает ли статус с одним из признаков.

    Сравнение по вхождению: SkyDNS отдаёт «exists: complete» для отчёта из
    кэша и «complete» для только что построенного — оба означают готовность.
    """
    return any(mark in status for mark in marks)


def _report_url(payload) -> str:
    """Ссылка на файл отчёта из конверта.

    Готовый отчёт не приходит в ответе — в ``message`` лежит адрес JSON-файла.
    """
    if not isinstance(payload, dict):
        return ""
    for key in ("message", "url", "link", "file", "result_url"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip().startswith(("http://", "https://")):
            return value.strip()
    return ""


def _payload_data(payload):
    """Достать полезную нагрузку, если ответ обёрнут в конверт."""
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return None
    for key in DATA_KEYS:
        if key in payload:
            nested = payload[key]
            if isinstance(nested, (list, dict)):
                return nested
    return None


def _found_of_type(payload, wanted):
    """Найти в ответе значение нужного типа: в нём самом или в обёртке.

    Конверт статуса — тоже словарь, поэтому сам ответ засчитывается за данные,
    только если статуса в нём нет.
    """
    if isinstance(payload, wanted) and not _status_of(payload):
        return payload

    nested = _payload_data(payload)
    if isinstance(nested, wanted):
        return nested
    if nested is not None and nested is not payload:
        deeper = _payload_data(nested)
        if isinstance(deeper, wanted):
            return deeper
    return None


def _error_text(payload) -> str:
    """Сообщение об ошибке из ответа: DRF и подобные кладут его по-разному."""
    if not isinstance(payload, dict):
        return ""
    for key in ("detail", "error", "message", "error_message", "reason"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, dict):
            nested = _error_text(value)
            if nested:
                return nested
    return ""


@dataclass
class SkydnsConfig:
    base_url: str = DEFAULT_BASE_URL
    user_id: str = ""
    token: str = ""
    # Профили (ident) через запятую. Пусто — отчёт по всем профилям.
    profile_ids: str = ""
    timezone: str = "UTC"
    verify_ssl: bool = True
    timeout: int = 90
    # Сколько всего ждать готовности асинхронного отчёта, секунд.
    report_timeout: int = REPORT_TIMEOUT

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.user_id and self.token)

    def profile_list(self) -> list:
        """Разобрать список профилей в формат, который принимает API."""
        items = []
        for chunk in (self.profile_ids or "").replace(";", ",").split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            items.append(int(chunk) if chunk.lstrip("-").isdigit() else chunk)
        return items


@dataclass
class Category:
    id: int
    title: str = ""
    is_dangerous: bool = False
    requests: int = 0
    blocks: int = 0


@dataclass
class DomainStat:
    """Строка отчёта по доменам."""

    domain: str
    requests: int = 0
    blocks: int = 0
    cat_ids: list = field(default_factory=list)
    # Заполняются приложением после сопоставления со справочником категорий.
    category: str = ""
    category_title: str = ""
    profile: str = ""


@dataclass
class DeviceStat:
    """Устройство, обращавшееся к домену."""

    token: int = 0
    ipv4: list = field(default_factory=list)
    ipv6: list = field(default_factory=list)
    secure: bool = False
    requests: int = 0
    blocks: int = 0

    @property
    def is_gateway(self) -> bool:
        """Трафик без агента — виден только адрес шлюза."""
        return int(self.token or 0) == GATEWAY_TOKEN

    @property
    def addresses(self) -> list:
        """Адреса устройства, кроме заглушек вида ``::``."""
        out = [a for a in (self.ipv4 or []) if a and a not in ("0.0.0.0",)]
        out += [a for a in (self.ipv6 or []) if a and a not in ("::",)]
        return out


def _ssl_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _normalize_base(base_url: str) -> str:
    base = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base


def build_period(
    start: date | None = None,
    end: date | None = None,
    period: str = "range",
    timezone: str = "UTC",
    profile_ids: list | None = None,
) -> dict:
    """Собрать стандартные аргументы периода из инструкции."""
    payload: dict = {"period": period, "timezone": timezone or "UTC"}
    if period == "range":
        if not start:
            raise SkydnsError("Для периода range нужна дата начала.")
        payload["start"] = start.isoformat()
        if end:
            payload["end"] = end.isoformat()
    elif period == "date":
        payload["date"] = (start or date.today()).isoformat()
    if profile_ids:
        payload["profile_ids"] = profile_ids
    return payload


class SkydnsClient:
    """Обращение к Proxy Stat API SkyDNS."""

    def __init__(self, config: SkydnsConfig) -> None:
        self.config = config
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_ssl_context(config.verify_ssl))
        )

    # --- низкий уровень ---------------------------------------------------

    def _url(self, method: str) -> str:
        return _normalize_base(self.config.base_url) + API_TEMPLATE.format(
            user_id=urllib.parse.quote(str(self.config.user_id).strip()),
            method=method,
        )

    def _call(self, method: str, payload: dict):
        if not self.config.is_configured:
            raise SkydnsError(
                "SkyDNS не настроен: укажите ID пользователя и токен API "
                "в разделе «Настройки»."
            )

        url = self._url(method)
        body = json.dumps(payload).encode()
        request = urllib.request.Request(url, data=body, headers={
            "Authorization": f"Token {self.config.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        })

        try:
            with self._opener.open(request, timeout=self.config.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            if exc.code in (401, 403):
                raise SkydnsError(
                    f"SkyDNS отклонил токен ({exc.code}). Проверьте токен и ID "
                    f"пользователя в настройках. {detail}"
                ) from exc
            if exc.code == 404:
                raise SkydnsError(
                    f"Метод {method} не найден ({url}). Проверьте ID пользователя "
                    f"в адресе. {detail}"
                ) from exc
            raise SkydnsError(
                f"SkyDNS вернул ошибку {exc.code} на {method}. {detail}"
            ) from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise SkydnsError(f"Не удалось связаться со SkyDNS: {exc}") from exc

        if not raw.strip():
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SkydnsError(
                f"SkyDNS вернул не JSON на метод {method}. "
                "Проверьте адрес API и ID пользователя."
            ) from exc

    def _report(self, method: str, payload: dict, expect: str = "list"):
        """Получить отчёт, дождавшись его формирования.

        Отчёт строится асинхронно: пока он не готов, приходит конверт со
        статусом. Здесь запрос повторяется до готовности, но не дольше
        ``report_timeout`` — операция идёт синхронно в веб-запросе.
        """
        deadline = time.monotonic() + max(self.config.report_timeout, 1)
        delay = POLL_START
        last = None

        while True:
            last = self._call(method, payload)
            data = self._unwrap(method, last, expect)
            if data is not None:
                return data

            if time.monotonic() >= deadline:
                raise SkydnsError(
                    f"SkyDNS не успел сформировать отчёт {method} за "
                    f"{self.config.report_timeout} с. Последний ответ: "
                    f"{_excerpt(last)}"
                )
            time.sleep(min(delay, max(0, deadline - time.monotonic())))
            delay = min(delay * 2, POLL_MAX)

    def _unwrap(self, method: str, payload, expect: str):
        """Разобрать ответ: данные, «ещё не готово» или ошибка.

        Возвращает данные нужного типа либо ``None``, если отчёт ещё строится.
        Всё остальное — ошибка с куском реального ответа: без него в интерфейсе
        видно только «неожиданный ответ», и разобраться невозможно.
        """
        wanted = list if expect == "list" else dict
        status = _status_of(payload)

        if status:
            if _status_is(status, STATUS_FAILED_MARKS):
                raise SkydnsError(
                    f"SkyDNS вернул ошибку на {method}: "
                    f"{_error_text(payload) or status}. "
                    f"Ответ: {_excerpt(payload)}"
                )
            if _status_is(status, STATUS_READY_MARKS):
                # Готовый отчёт лежит файлом по ссылке из конверта.
                url = _report_url(payload)
                if url:
                    return self._check_type(method, self._fetch_report(url),
                                            wanted, source=url)
                data = _found_of_type(payload, wanted)
                if data is not None:
                    return data
                raise SkydnsError(
                    f"SkyDNS сообщил о готовности отчёта {method}, но не дал "
                    f"ни ссылки, ни данных. Ответ: {_excerpt(payload)}"
                )
            # Отчёт ещё строится — вызывающий подождёт и спросит снова.
            return None

        # Ответ без статуса: данные пришли прямо в нём или в обёртке.
        data = _found_of_type(payload, wanted)
        if data is not None:
            return data

        message = _error_text(payload)
        if message:
            raise SkydnsError(
                f"SkyDNS вернул ошибку на {method}: {message}. "
                f"Ответ: {_excerpt(payload)}"
            )

        raise SkydnsError(
            f"SkyDNS вернул неожиданный ответ на {method} "
            f"(ожидался {'список' if wanted is list else 'объект'}). "
            f"Ответ: {_excerpt(payload)}"
        )

    def _check_type(self, method: str, payload, wanted, source: str = ""):
        """Проверить, что скачанный отчёт нужного вида."""
        data = _found_of_type(payload, wanted)
        if data is not None:
            return data
        raise SkydnsError(
            f"Файл отчёта {method} не похож на "
            f"{'список' if wanted is list else 'объект'}"
            f"{f' ({source})' if source else ''}. Содержимое: {_excerpt(payload)}"
        )

    def _fetch_report(self, url: str):
        """Скачать готовый отчёт по ссылке из конверта.

        Токен сюда не отправляется: файл лежит на отдельном хосте выдачи, а
        ссылка уже одноразовая — незачем светить токен на другом домене.
        """
        request = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        })
        try:
            with self._opener.open(request, timeout=self.config.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise SkydnsError(
                f"Не удалось скачать отчёт SkyDNS ({exc.code}): {url}"
            ) from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise SkydnsError(
                f"Не удалось скачать отчёт SkyDNS: {exc}"
            ) from exc

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SkydnsError(
                "Файл отчёта SkyDNS оказался не JSON."
            ) from exc

    def _period(self, start: date | None, end: date | None,
                period: str = "range") -> dict:
        return build_period(
            start=start, end=end, period=period,
            timezone=self.config.timezone,
            profile_ids=self.config.profile_list(),
        )

    # --- методы API -------------------------------------------------------

    def total_activity(self, start: date, end: date | None = None) -> dict:
        """Сводка активности — используется для проверки подключения."""
        return self._report(M_TOTAL, self._period(start, end), expect="dict")

    def categories(self, start: date, end: date | None = None,
                   lang: str = "ru") -> list:
        """Справочник категорий с флагом is_dangerous и счётчиками."""
        payload = self._period(start, end)
        if lang:
            payload["lang"] = lang
        rows = self._report(M_CATEGORIES, payload)

        result = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            cat = row.get("cat") or {}
            if cat.get("id") is None:
                continue
            result.append(Category(
                id=int(cat["id"]),
                title=str(cat.get("title") or "").strip(),
                is_dangerous=bool(cat.get("is_dangerous")),
                requests=int(row.get("requests") or 0),
                blocks=int(row.get("blocks") or 0),
            ))
        return result

    def domains(
        self,
        start: date,
        end: date | None = None,
        cats: list | None = None,
        limit: int | None = None,
        order_by: str = "-visits",
    ) -> list:
        """Домены с числом запросов и категориями.

        ``cats`` — список ID категорий: так опасные домены забираются одним
        запросом, без выкачивания всей статистики организации.
        """
        payload = self._period(start, end)
        if cats:
            payload["cats"] = list(cats)
        if limit:
            payload["limit"] = int(limit)
        if order_by:
            payload["order_by"] = order_by

        rows = self._report(M_DOMAINS, payload)

        result = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            domain = _clean_domain(row.get("domain"))
            if not domain:
                continue
            result.append(DomainStat(
                domain=domain,
                requests=int(row.get("requests") or 0),
                blocks=int(row.get("blocks") or 0),
                cat_ids=[int(c) for c in (row.get("cat_ids") or [])
                         if str(c).lstrip("-").isdigit()],
            ))
        return result

    def devices(
        self,
        start: date,
        end: date | None = None,
        domains: list | None = None,
        limit: int | None = None,
    ) -> list:
        """Устройства, обращавшиеся к указанным доменам."""
        payload = self._period(start, end)
        if domains:
            payload["domains"] = list(domains)
        if limit:
            payload["limit"] = int(limit)

        rows = self._report(M_DEVICES, payload)

        result = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            result.append(DeviceStat(
                token=int(row.get("token") or 0),
                ipv4=[str(a) for a in (row.get("ipv4") or []) if a],
                ipv6=[str(a) for a in (row.get("ipv6") or []) if a],
                secure=bool(row.get("secure")),
                requests=int(row.get("requests") or 0),
                blocks=int(row.get("blocks") or 0),
            ))
        return result

    def probe(self, method: str, start: date, end: date | None = None) -> dict:
        """Сырой ответ метода — для диагностики в интерфейсе.

        Формат отчётов у разных подписок отличается, а разбор ответа делается
        «вслепую». Эта кнопка показывает, что именно вернул сервер.
        """
        payload = self._period(start, end)
        return {
            "url": self._url(method),
            "request": payload,
            "response": self._call(method, payload),
        }

    def detailed(
        self,
        start: date,
        end: date | None = None,
        domain: str = "",
        cats: list | None = None,
        limit: int | None = 5000,
    ) -> list:
        """Детализация: домен, адрес, токен и профиль в одной строке.

        Главный способ узнать, какое устройство ходило на какой домен: один
        отчёт вместо запроса устройств по каждому домену отдельно.
        """
        payload = self._period(start, end)
        if domain:
            payload["domain"] = domain
        if cats:
            payload["cats"] = list(cats)
        if limit:
            payload["limit"] = int(limit)

        rows = self._report(M_DETAILED, payload)
        return [row for row in rows if isinstance(row, dict)]

    def hosts_by_domain(
        self,
        start: date,
        end: date | None = None,
        cats: list | None = None,
        limit: int | None = 5000,
    ) -> dict:
        """Сопоставить домены и устройства, которые к ним обращались.

        Возвращает ``{домен: [DeviceStat, ...]}``. Записи с ``token == 0``
        отбрасываются: это трафик через шлюз, конечный хост по нему неизвестен
        и ищется в SIEM.
        """
        found: dict = {}
        for row in self.detailed(start, end, cats=cats, limit=limit):
            domain = _clean_domain(row.get("domain"))
            token = int(row.get("token") or 0)
            if not domain or token == GATEWAY_TOKEN:
                continue

            addresses = []
            for key in ("ipv4", "ipv6"):
                value = row.get(key)
                if isinstance(value, str):
                    addresses.append(value)
                elif isinstance(value, list):
                    addresses.extend(str(a) for a in value if a)

            by_token = found.setdefault(domain, {})
            device = by_token.get(token)
            if device is None:
                device = DeviceStat(token=token, secure=bool(row.get("secure")))
                by_token[token] = device
            for address in addresses:
                if address in ("::", "0.0.0.0", ""):
                    continue
                target = device.ipv6 if ":" in address else device.ipv4
                if address not in target:
                    target.append(address)
            device.requests += int(row.get("requests") or 0)
            device.blocks += int(row.get("blocks") or 0)

        return {domain: list(by_token.values())
                for domain, by_token in found.items()}


def _clean_domain(value) -> str:
    """Привести значение к домену: без схемы, пути, порта и звёздочки."""
    domain = str(value or "").strip().lower().strip(".")
    if not domain:
        return ""
    if "//" in domain:
        domain = urllib.parse.urlsplit(domain).netloc or domain
    domain = domain.split("/")[0].split(":")[0].lstrip("*.")
    if "." not in domain:
        return ""
    return domain


def dangerous_ids(categories: list) -> set:
    """ID опасных категорий: из ответа API, иначе — из приложения к инструкции."""
    ids = {cat.id for cat in categories if cat.is_dangerous}
    return ids or set(DANGEROUS_CATEGORY_IDS)


def describe_categories(cat_ids: list, catalogue: dict) -> tuple:
    """Человекочитаемое название категорий домена.

    Возвращает (код основной категории, названия через запятую). Основной
    считается первая опасная категория — именно она интересна в разборе.
    """
    titles = []
    primary = ""
    for cat_id in cat_ids or []:
        info = catalogue.get(int(cat_id))
        title = (info.title if info else "") or DANGEROUS_CATEGORY_IDS.get(
            int(cat_id), f"категория {cat_id}"
        )
        titles.append(title)
        is_dangerous = info.is_dangerous if info else int(cat_id) in DANGEROUS_CATEGORY_IDS
        if not primary and is_dangerous:
            primary = str(cat_id)
    if not primary and cat_ids:
        primary = str(cat_ids[0])
    return primary, ", ".join(dict.fromkeys(titles))


# --- Импорт выгрузки из личного кабинета ----------------------------------

CSV_FIELDS = {
    "domain": ["domain", "домен", "сайт", "site", "host"],
    "requests": ["requests", "запросы", "обращения", "visits", "count"],
    "blocks": ["blocks", "блокировки", "blocked"],
    "category": ["category", "категория", "cat", "категории"],
}


def _pick(row: dict, names: list) -> str:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        value = lowered.get(name)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _to_int(value: str) -> int:
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    return int(digits) if digits else 0


def parse_csv(data: bytes) -> list:
    """Разобрать выгрузку статистики по сайтам из личного кабинета SkyDNS.

    Запасной путь на случай, если токен Proxy Stat API ещё не выпущен.
    """
    for encoding in ("utf-8-sig", "cp1251", "utf-8"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise SkydnsError("Не удалось определить кодировку файла статистики.")

    sample = text[:4096]
    try:
        delimiter = csv.Sniffer().sniff(sample, delimiters=";,\t").delimiter
    except csv.Error:
        delimiter = ";" if sample.count(";") >= sample.count(",") else ","

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise SkydnsError("В файле не найдена строка заголовков.")

    stats = []
    for row in reader:
        if not any(row.values()):
            continue
        domain = _clean_domain(_pick(row, CSV_FIELDS["domain"]))
        if not domain:
            continue
        category = _pick(row, CSV_FIELDS["category"])
        stats.append(DomainStat(
            domain=domain,
            requests=_to_int(_pick(row, CSV_FIELDS["requests"])),
            blocks=_to_int(_pick(row, CSV_FIELDS["blocks"])),
            category=category,
            category_title=category,
        ))

    if not stats:
        raise SkydnsError(
            "В файле не найдено ни одного домена. Нужна колонка с доменом "
            "(domain / сайт / host)."
        )
    return stats
