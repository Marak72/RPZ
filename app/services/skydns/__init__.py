"""Сервис «Угрозы SkyDNS» — обращения на вредоносные ресурсы и поиск хостов.

Всё, что относится к сервису, лежит в этой папке::

    routes.py     страницы: дашборд, домены, конечные хосты, журналы, настройки
    forms.py      формы загрузки статистики и настроек SkyDNS / MaxPatrol SIEM
    models.py     ThreatDomain / ThreatHost / SiemQueryLog / …
    lib/
        skydns_client.py  API личного кабинета SkyDNS
        siem_client.py    поиск событий в MaxPatrol SIEM
        exclusions.py     правила исключений доменов
        domains.py        разбор доменных имён
    templates/skydns/  страницы сервиса и его боковая навигация
"""
from . import models  # noqa: F401 — модели должны быть видны SQLAlchemy
from .routes import skydns_bp

__all__ = ["skydns_bp", "models"]
