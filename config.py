"""Конфигурация приложения.

Все секреты берутся из переменных окружения. Для разработки можно завести
файл .env (он в .gitignore) и подгружать его вручную перед запуском.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


class Config:
    # Ключ для подписи сессий Flask.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # SQLite в каталоге instance/.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(INSTANCE_DIR, "rpz.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Ключ Fernet для шифрования паролей SSH-учётных записей в БД.
    # Сгенерировать: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    RPZ_FERNET_KEY = os.environ.get("RPZ_FERNET_KEY")

    # Ограничение размера загружаемого письма (32 МБ — сканы в PDF бывают тяжёлыми).
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024

    # Каталог для хранения самих файлов писем ФСТЭК.
    LETTERS_DIR = os.environ.get("LETTERS_DIR", os.path.join(INSTANCE_DIR, "letters"))

    # VirusTotal: сколько индикаторов проверять за один пакетный запуск
    # (у бесплатного ключа лимит 4 запроса в минуту, 500 в сутки).
    VT_BATCH_LIMIT = int(os.environ.get("VT_BATCH_LIMIT", "8"))
    VT_TIMEOUT = int(os.environ.get("VT_TIMEOUT", "20"))

    # Таймаут SSH-подключения, секунды.
    SSH_TIMEOUT = int(os.environ.get("SSH_TIMEOUT", "15"))

    # Путь к файлу RPZ-зоны по умолчанию (можно переопределить в настройках УЗ).
    DEFAULT_ZONE_PATH = os.environ.get(
        "DEFAULT_ZONE_PATH", "/var/named/master/rpz.block.db"
    )

    # Выполнять фоновые задания (поиск в SIEM) прямо в обработчике запроса,
    # без отдельного потока. По умолчанию — только в тестах: там поток до
    # базы в памяти процесса не достучится. Полезно и для отладки.
    JOBS_RUN_INLINE = None

    # Работа за обратным прокси (nginx) на подпути, напр. /fstec.
    # При включении приложение доверяет заголовкам X-Forwarded-* (в т.ч.
    # X-Forwarded-Prefix) и помечает cookie сессии как Secure (только https).
    BEHIND_PROXY = os.environ.get("BEHIND_PROXY", "").lower() in ("1", "true", "yes")

    # Параметры безопасности cookie сессии.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = BEHIND_PROXY
