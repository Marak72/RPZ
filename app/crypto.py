"""Шифрование чувствительных данных (паролей SSH-учётных записей) через Fernet.

Ключ берётся из конфигурации приложения (RPZ_FERNET_KEY). Без ключа операции
шифрования/расшифровки явно падают, чтобы нельзя было случайно сохранить
пароль в открытом виде.
"""
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _fernet() -> Fernet:
    key = current_app.config.get("RPZ_FERNET_KEY")
    if not key:
        raise RuntimeError(
            "RPZ_FERNET_KEY не задан. Сгенерируйте ключ: "
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt(plain: str) -> str:
    """Зашифровать строку, вернуть токен в виде строки для хранения в БД."""
    if plain is None:
        plain = ""
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    """Расшифровать токен из БД обратно в строку."""
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError(
            "Не удалось расшифровать пароль: неверный RPZ_FERNET_KEY "
            "или повреждённые данные."
        ) from exc
