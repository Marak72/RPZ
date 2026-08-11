"""Доступ к настройкам приложения (таблица app_settings).

Секретные значения (ключ VirusTotal, пароли к SkyDNS и MaxPatrol SIEM)
хранятся зашифрованными тем же ключом Fernet, что и пароли SSH.
"""
from __future__ import annotations

from .crypto import decrypt, encrypt
from .extensions import db
from .models import AppSetting

KEY_VT_API = "vt_api_key"
KEY_TASK_COUNTER = "tasks_last_number"  # выданный номер задачи
KEY_PROTECTED = "protected_domains"

# --- SkyDNS (Proxy Stat API) ----------------------------------------------
KEY_SKYDNS_URL = "skydns_base_url"
KEY_SKYDNS_USER_ID = "skydns_user_id"            # {user_id} в адресе API
KEY_SKYDNS_TOKEN = "skydns_token"                # секрет: Authorization: Token
KEY_SKYDNS_PROFILE = "skydns_profile"            # profile_ids через запятую
KEY_SKYDNS_TZ = "skydns_timezone"                # timezone для отчётов
KEY_SKYDNS_DAYS = "skydns_days"                  # глубина выборки, дней
KEY_SKYDNS_VERIFY = "skydns_verify_ssl"
KEY_SKYDNS_LIMIT = "skydns_limit"                # лимит доменов в отчёте
KEY_SKYDNS_DETAIL_LIMIT = "skydns_detail_limit"  # лимит строк детализации
KEY_SKYDNS_TIMEOUT = "skydns_report_timeout"     # ожидание отчёта, секунд
KEY_SKYDNS_AUTO_DEVICES = "skydns_auto_devices"  # искать устройства при выгрузке

# --- MaxPatrol SIEM -------------------------------------------------------
KEY_SIEM_URL = "siem_base_url"
KEY_SIEM_AUTH_MODE = "siem_auth_mode"            # session | token
KEY_SIEM_AUTH_TYPE = "siem_auth_type"            # local | ldap (для session)
KEY_SIEM_USERNAME = "siem_username"
KEY_SIEM_PASSWORD = "siem_password"              # секрет
KEY_SIEM_CLIENT_ID = "siem_client_id"
KEY_SIEM_CLIENT_SECRET = "siem_client_secret"    # секрет
KEY_SIEM_VERIFY = "siem_verify_ssl"
KEY_SIEM_FILTER = "siem_filter_template"         # шаблон фильтра с {domain}
KEY_SIEM_GROUP_FIELD = "siem_group_field"        # поле группировки
KEY_SIEM_WINDOW = "siem_window_hours"            # окно поиска, часов
# Предел событий на один домен. Ключ новый: раньше настройка ограничивала
# число строк в одном ответе, теперь — сколько событий всего дочитывать
# страницами. Старое значение (обычно 500) под новым смыслом означало бы
# «взять только первые 500 событий» — незаметное урезание выборки.
KEY_SIEM_MAX_EVENTS = "siem_max_events"
KEY_SIEM_TIMEOUT = "siem_timeout"                # таймаут запроса, секунд
# Сколько доменов уходит в SIEM одним запросом: условия объединяются через
# or, события раскладываются по доменам на нашей стороне. Единица возвращает
# прежнее поведение — отдельный запрос на каждый домен.
KEY_SIEM_CHUNK = "siem_domains_per_query"

# Фильтр событий по домену.
#
# Разбирая DNS-запрос, SIEM раскладывает имя по полям: в datafield3 попадает
# базовый домен (autodesk.com), в datafield4 — часть слева (update.delivery),
# а полное имя целиком — в datafield6. Поэтому искать только по datafield3
# недостаточно: так находятся домены вида example.com, а любой поддомен —
# а это почти вся статистика SkyDNS — не совпадает ни с чем.
DEFAULT_SIEM_FILTER = ('datafield1 = "{domain}" or datafield3 = "{domain}"'
                       ' or datafield6 = "{domain}"')

#: Шаблоны, которые портал ставил раньше и которые заведомо неполны.
#: Сохранённое значение из этого списка заменяется текущим: оператор его не
#: выбирал осознанно, это наше же умолчание, и оно молча не находило хосты.
LEGACY_SIEM_FILTERS = (
    'datafield1 = "{domain}" or datafield3 = "{domain}"',
)
# Конечный хост — это тот, кто обратился к домену, то есть источник события.
# Можно перечислить несколько полей через запятую: адрес возьмётся из первого
# заполненного (в событиях разных источников он лежит по-разному).
DEFAULT_SIEM_GROUP_FIELD = "src.ip"
DEFAULT_SIEM_TIMEOUT = 120
DEFAULT_SIEM_MAX_EVENTS = 20000
DEFAULT_SIEM_CHUNK = 20

DEFAULT_SKYDNS_TZ = "Asia/Yekaterinburg"
DEFAULT_SKYDNS_LIMIT = 2000


def get_setting(key: str, default: str = "") -> str:
    row = db.session.get(AppSetting, key)
    if not row or not row.value:
        return default
    if row.is_secret:
        try:
            return decrypt(row.value)
        except RuntimeError:
            return default
    return row.value


def set_setting(key: str, value: str, is_secret: bool = False) -> None:
    row = db.session.get(AppSetting, key)
    stored = encrypt(value) if (is_secret and value) else value
    if row is None:
        row = AppSetting(key=key, value=stored, is_secret=is_secret)
        db.session.add(row)
    else:
        row.value = stored
        row.is_secret = is_secret


def get_bool(key: str, default: bool = False) -> bool:
    raw = get_setting(key, "")
    if raw == "":
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def get_int(key: str, default: int) -> int:
    try:
        return int(get_setting(key, "") or default)
    except (TypeError, ValueError):
        return default


def get_vt_key() -> str:
    return get_setting(KEY_VT_API)


def _lines(raw: str) -> list[str]:
    return [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def get_protected_domains() -> set[str]:
    """Домены, которые запрещено выгружать в блокировку."""
    return {
        line.lower().lstrip("*.").rstrip(".")
        for line in _lines(get_setting(KEY_PROTECTED))
    }


def get_siem_filter_template() -> str:
    stored = get_setting(KEY_SIEM_FILTER, "")
    if not stored or stored.strip() in LEGACY_SIEM_FILTERS:
        return DEFAULT_SIEM_FILTER
    return stored


def get_siem_group_field() -> str:
    return get_setting(KEY_SIEM_GROUP_FIELD, DEFAULT_SIEM_GROUP_FIELD)


def load_siem_config():
    """Собрать параметры подключения к MaxPatrol SIEM из настроек."""
    from .services.siem_client import DEFAULT_CLIENT_ID, SiemConfig

    return SiemConfig(
        base_url=get_setting(KEY_SIEM_URL),
        auth_mode=get_setting(KEY_SIEM_AUTH_MODE, "session"),
        auth_type=get_setting(KEY_SIEM_AUTH_TYPE, "local"),
        username=get_setting(KEY_SIEM_USERNAME),
        password=get_setting(KEY_SIEM_PASSWORD),
        client_id=get_setting(KEY_SIEM_CLIENT_ID, DEFAULT_CLIENT_ID),
        client_secret=get_setting(KEY_SIEM_CLIENT_SECRET),
        verify_ssl=get_bool(KEY_SIEM_VERIFY, False),
        limit=get_int(KEY_SIEM_MAX_EVENTS, DEFAULT_SIEM_MAX_EVENTS),
        timeout=get_int(KEY_SIEM_TIMEOUT, DEFAULT_SIEM_TIMEOUT),
    )


def load_skydns_config():
    """Собрать параметры подключения к Proxy Stat API SkyDNS из настроек."""
    from .services.skydns_client import DEFAULT_BASE_URL, SkydnsConfig

    return SkydnsConfig(
        base_url=get_setting(KEY_SKYDNS_URL, DEFAULT_BASE_URL),
        user_id=get_setting(KEY_SKYDNS_USER_ID),
        token=get_setting(KEY_SKYDNS_TOKEN),
        profile_ids=get_setting(KEY_SKYDNS_PROFILE),
        timezone=get_setting(KEY_SKYDNS_TZ, DEFAULT_SKYDNS_TZ),
        verify_ssl=get_bool(KEY_SKYDNS_VERIFY, True),
        report_timeout=get_int(KEY_SKYDNS_TIMEOUT, 300),
    )
