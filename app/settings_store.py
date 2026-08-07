"""Доступ к настройкам приложения (таблица app_settings).

Секретные значения (ключ VirusTotal) хранятся зашифрованными тем же ключом
Fernet, что и пароли SSH.
"""
from __future__ import annotations

from .crypto import decrypt, encrypt
from .extensions import db
from .models import AppSetting

KEY_VT_API = "vt_api_key"
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


def get_vt_key() -> str:
    return get_setting(KEY_VT_API)


def get_protected_domains() -> set[str]:
    """Домены, которые запрещено выгружать в блокировку."""
    raw = get_setting(KEY_PROTECTED)
    return {
        line.strip().lower().lstrip("*.").rstrip(".")
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
