"""Клиент статистики SkyDNS: домены «опасных» категорий из трафика организации.

Из личного кабинета SkyDNS забирается статистика обращений по доменам, из неё
оставляются только категории, связанные с безопасностью (malware, ботнеты,
фишинг и т. п.). Дальше по каждому такому домену сервис идёт в MaxPatrol SIEM
за конечными хостами.

Про совместимость. В инсталляциях SkyDNS отличаются и путь метода статистики,
и имена полей в ответе, поэтому клиент сделан адаптером: путь метода и
сопоставление полей задаются в настройках приложения, а разбор ответа терпим
к обёрткам (``data``/``result``/``items``/``rows``). Если API недоступен,
ровно те же данные грузятся выгрузкой CSV из личного кабинета.

Реализация — только на стандартной библиотеке (как vt_client и siem_client).
"""
from __future__ import annotations

import base64
import csv
import io
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date

DEFAULT_BASE_URL = "https://www.skydns.ru"
DEFAULT_STATS_PATH = "/api/v1/stats/domains"
USER_AGENT = "rpz-portal/1.0"

# Сопоставление полей ответа по умолчанию: слева — что нужно приложению,
# справа — имена, которые встречаются в выгрузках SkyDNS.
DEFAULT_FIELD_MAP = {
    "domain": ["domain", "site", "host", "url", "name", "домен", "сайт"],
    "category": ["category", "cat", "category_code", "категория"],
    "category_title": ["category_title", "category_name", "cat_name", "название"],
    "requests": ["requests", "count", "hits", "queries", "запросы", "обращения"],
    "blocks": ["blocks", "blocked", "block_count", "блокировки"],
    "profile": ["profile", "ident", "user", "group", "профиль"],
}

# Подстроки в названии категории, по которым она считается связанной с
# безопасностью, даже если точного совпадения со списком настроек нет.
SECURITY_HINTS = (
    "malware", "вредонос", "botnet", "ботнет", "phishing", "фишинг",
    "spam", "спам", "spyware", "шпион", "crypto", "майнинг", "mining",
    "compromised", "взлом", "anonymizer", "анонимайзер", "proxy", "tor",
    "c2", "command", "exploit", "эксплойт", "ransom", "троян", "trojan",
    "scam", "мошен", "hack", "угроз", "threat", "danger", "опасн",
)


class SkydnsError(Exception):
    """Ошибка обращения к SkyDNS, пригодная для показа оператору."""


@dataclass
class SkydnsConfig:
    base_url: str = DEFAULT_BASE_URL
    stats_path: str = DEFAULT_STATS_PATH
    login: str = ""
    password: str = ""
    token: str = ""
    profile: str = ""
    verify_ssl: bool = True
    timeout: int = 30
    field_map: dict = field(default_factory=dict)

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and (self.token or (self.login and self.password)))


@dataclass
class DomainStat:
    """Строка статистики: домен, его категория и счётчики обращений."""

    domain: str
    category: str = ""
    category_title: str = ""
    requests: int = 0
    blocks: int = 0
    profile: str = ""


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


def is_security_category(
    category: str, category_title: str, allowed: list[str]
) -> bool:
    """Относится ли категория к безопасности.

    Сначала проверяется точное совпадение со списком из настроек, затем —
    характерные подстроки: у SkyDNS коды категорий в разных выгрузках
    отличаются, и жёсткий список легко «промахивается».
    """
    haystack = f"{category} {category_title}".strip().lower()
    if not haystack:
        return False
    for item in allowed:
        item = item.strip().lower()
        if item and item in haystack:
            return True
    return any(hint in haystack for hint in SECURITY_HINTS)


def _pick(row: dict, names: list[str]) -> str:
    """Взять из строки первое непустое поле с одним из подходящих имён."""
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        value = lowered.get(name.strip().lower())
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _to_int(value: str) -> int:
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    return int(digits) if digits else 0


def _field_names(field_map: dict, key: str) -> list[str]:
    """Имена полей для ключа: сначала заданные оператором, потом типовые."""
    custom = field_map.get(key) if field_map else None
    names: list[str] = []
    if isinstance(custom, str) and custom.strip():
        names.append(custom.strip())
    elif isinstance(custom, list):
        names.extend(str(item) for item in custom if str(item).strip())
    names.extend(DEFAULT_FIELD_MAP.get(key, []))
    return names


def _rows_from_payload(payload) -> list[dict]:
    """Найти список строк статистики в ответе произвольной формы."""
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "result", "results", "items", "rows", "stats", "domains"):
        nested = payload.get(key)
        if isinstance(nested, list):
            return [row for row in nested if isinstance(row, dict)]
        if isinstance(nested, dict):
            deeper = _rows_from_payload(nested)
            if deeper:
                return deeper
    # Ответ вида {"example.com": {...}, ...}.
    rows = []
    for key, value in payload.items():
        if isinstance(value, dict):
            row = dict(value)
            row.setdefault("domain", key)
            rows.append(row)
    return rows


def parse_rows(rows: list[dict], field_map: dict | None = None) -> list[DomainStat]:
    """Превратить строки ответа/CSV в список DomainStat."""
    field_map = field_map or {}
    stats: list[DomainStat] = []
    for row in rows:
        domain = _pick(row, _field_names(field_map, "domain")).lower()
        domain = domain.strip().strip(".").lstrip("*.")
        if not domain or "." not in domain:
            continue
        # Иногда в выгрузке лежит URL целиком — оставляем только хост.
        if "//" in domain:
            domain = urllib.parse.urlsplit(domain).netloc or domain
        domain = domain.split("/")[0].split(":")[0]
        stats.append(DomainStat(
            domain=domain,
            category=_pick(row, _field_names(field_map, "category")),
            category_title=_pick(row, _field_names(field_map, "category_title")),
            requests=_to_int(_pick(row, _field_names(field_map, "requests"))),
            blocks=_to_int(_pick(row, _field_names(field_map, "blocks"))),
            profile=_pick(row, _field_names(field_map, "profile")),
        ))
    return stats


def parse_csv(data: bytes, field_map: dict | None = None) -> list[DomainStat]:
    """Разобрать выгрузку статистики из личного кабинета SkyDNS.

    Разделитель определяется автоматически (в русской локали Excel это ';').
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
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ";" if sample.count(";") >= sample.count(",") else ","

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise SkydnsError("В файле не найдена строка заголовков.")
    rows = [row for row in reader if any(row.values())]
    stats = parse_rows(rows, field_map)
    if not stats:
        raise SkydnsError(
            "В файле не найдено ни одного домена. Проверьте, что есть колонка "
            "с доменом (domain / сайт) — иначе задайте сопоставление полей "
            "в настройках."
        )
    return stats


class SkydnsClient:
    """Обращение к API статистики SkyDNS."""

    def __init__(self, config: SkydnsConfig) -> None:
        self.config = config
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_ssl_context(config.verify_ssl))
        )

    def _headers(self) -> dict:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        elif self.config.login and self.config.password:
            pair = f"{self.config.login}:{self.config.password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(pair).decode()
        return headers

    def fetch_domains(self, start: date, end: date) -> list[DomainStat]:
        """Забрать статистику по доменам за период."""
        if not self.config.is_configured:
            raise SkydnsError(
                "SkyDNS не настроен: укажите адрес и учётные данные "
                "в разделе «Настройки»."
            )

        params = {
            "start": start.isoformat(),
            "end": end.isoformat(),
        }
        if self.config.profile:
            params["ident"] = self.config.profile

        path = self.config.stats_path or DEFAULT_STATS_PATH
        url = _normalize_base(self.config.base_url) + path
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)

        request = urllib.request.Request(url, headers=self._headers())
        try:
            with self._opener.open(request, timeout=self.config.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            if exc.code in (401, 403):
                raise SkydnsError(
                    f"SkyDNS отклонил учётные данные ({exc.code}). {detail}"
                ) from exc
            if exc.code == 404:
                raise SkydnsError(
                    f"Метод статистики не найден ({url}). Проверьте путь метода "
                    "в настройках — он отличается между версиями API SkyDNS."
                ) from exc
            raise SkydnsError(f"SkyDNS вернул ошибку {exc.code}. {detail}") from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise SkydnsError(f"Не удалось связаться со SkyDNS: {exc}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SkydnsError(
                "SkyDNS вернул не JSON. Возможно, путь метода статистики "
                "указан неверно."
            ) from exc

        rows = _rows_from_payload(payload)
        if not rows:
            raise SkydnsError(
                "Ответ SkyDNS разобран, но строк статистики в нём нет. "
                "Проверьте период и профиль."
            )
        return parse_rows(rows, self.config.field_map)
