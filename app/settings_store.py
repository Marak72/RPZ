"""Доступ к настройкам приложения (таблица app_settings).

Секретные значения (ключ VirusTotal, пароли к SkyDNS и MaxPatrol SIEM)
хранятся зашифрованными тем же ключом Fernet, что и пароли SSH.
"""
from __future__ import annotations

from .crypto import decrypt, encrypt
from .extensions import db
from .models import AppSetting

KEY_VT_API = "vt_api_key"
KEY_PROTECTED = "protected_domains"

# --- SkyDNS ---------------------------------------------------------------
KEY_SKYDNS_URL = "skydns_base_url"
KEY_SKYDNS_LOGIN = "skydns_login"
KEY_SKYDNS_PASSWORD = "skydns_password"          # секрет
KEY_SKYDNS_TOKEN = "skydns_token"                # секрет (если API по токену)
KEY_SKYDNS_PROFILE = "skydns_profile"            # ident/профиль организации
KEY_SKYDNS_CATEGORIES = "skydns_categories"      # отслеживаемые категории
KEY_SKYDNS_DAYS = "skydns_days"                  # глубина выборки, дней
KEY_SKYDNS_VERIFY = "skydns_verify_ssl"
KEY_SKYDNS_STATS_PATH = "skydns_stats_path"      # путь метода статистики
KEY_SKYDNS_MAP = "skydns_field_map"              # сопоставление полей ответа

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
KEY_SIEM_LIMIT = "siem_limit"                    # максимум строк ответа

# Фильтр из рабочей практики: домен в SkyDNS-событиях попадает в datafield1
# (запрошенное имя) либо datafield3 (имя из ответа/CNAME).
DEFAULT_SIEM_FILTER = 'datafield1 = "{domain}" or datafield3 = "{domain}"'
DEFAULT_SIEM_GROUP_FIELD = "dst.host"

# Категории SkyDNS, связанные с безопасностью. Реальные коды подставляются
# из инструкции SkyDNS — здесь разумный стартовый набор.
DEFAULT_SKYDNS_CATEGORIES = "\n".join((
    "malware",
    "botnet",
    "phishing",
    "spam",
    "spyware",
    "cryptomining",
    "compromised",
    "anonymizer",
))


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


def get_skydns_categories() -> list[str]:
    """Категории SkyDNS, которые считаем угрозами безопасности."""
    raw = get_setting(KEY_SKYDNS_CATEGORIES, DEFAULT_SKYDNS_CATEGORIES)
    return [line.lower() for line in _lines(raw)]


def get_siem_filter_template() -> str:
    return get_setting(KEY_SIEM_FILTER, DEFAULT_SIEM_FILTER)


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
        limit=get_int(KEY_SIEM_LIMIT, 500),
    )


def load_skydns_config():
    """Собрать параметры подключения к SkyDNS из настроек."""
    import json

    from .services.skydns_client import (
        DEFAULT_BASE_URL,
        DEFAULT_STATS_PATH,
        SkydnsConfig,
    )

    raw_map = get_setting(KEY_SKYDNS_MAP, "")
    try:
        field_map = json.loads(raw_map) if raw_map.strip() else {}
    except (ValueError, TypeError):
        field_map = {}
    if not isinstance(field_map, dict):
        field_map = {}

    return SkydnsConfig(
        base_url=get_setting(KEY_SKYDNS_URL, DEFAULT_BASE_URL),
        stats_path=get_setting(KEY_SKYDNS_STATS_PATH, DEFAULT_STATS_PATH),
        login=get_setting(KEY_SKYDNS_LOGIN),
        password=get_setting(KEY_SKYDNS_PASSWORD),
        token=get_setting(KEY_SKYDNS_TOKEN),
        profile=get_setting(KEY_SKYDNS_PROFILE),
        verify_ssl=get_bool(KEY_SKYDNS_VERIFY, True),
        field_map=field_map,
    )
