"""Сервис «РПЗ ФСТЭК» — блокировка доменов из писем ФСТЭК через RPZ BIND.

Всё, что относится к сервису, лежит в этой папке::

    routes.py     страницы: дашборд, письма, индикаторы, выгрузка, настройки
    forms.py      формы загрузки, ручного добавления, настроек SSH
    models.py     Letter / LetterFile / BlockEntry / UrlEntry / IocHash / …
    letters.py    разбор пачки файлов: реквизиты письма, группировка, сохранение
    lib/
        doc_parser.py  извлечение индикаторов из .docx/.odt/.pdf
        rpz_parser.py  разбор файла RPZ-зоны
        rpz_writer.py  безопасная запись зоны на боевой DNS-сервер
        ssh_client.py  подключение к DNS-серверу
    templates/fstec/  страницы сервиса и его боковая навигация
"""
from . import models  # noqa: F401 — модели должны быть видны SQLAlchemy
from .routes import fstec_bp

__all__ = ["fstec_bp", "models"]
