"""Доступ к настройкам приложения (таблица app_settings).

Здесь только механика хранения и те ключи, что общие для портала. Настройки
конкретного сервиса живут вместе с ним, например подключения к SkyDNS и
MaxPatrol SIEM — в ``app/services/skydns/settings.py``.

Секретные значения (ключ VirusTotal, пароли к внешним системам) хранятся
зашифрованными тем же ключом Fernet, что и пароли SSH.
"""
from __future__ import annotations

from .crypto import decrypt, encrypt
from .extensions import db
from .models import AppSetting

KEY_VT_API = "vt_api_key"
KEY_TASK_COUNTER = "tasks_last_number"  # выданный номер задачи
KEY_PROTECTED = "protected_domains"


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

