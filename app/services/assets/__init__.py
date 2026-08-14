"""Сервис «Узлы сети» — что за узел стоит за IP-адресом.

Всё, что относится к сервису, лежит в этой папке::

    routes.py     страницы: поиск, карточка адреса, списки, выгрузка, настройки
    forms.py      формы поиска, ручного добавления и настроек
    models.py     NetworkHost / AdComputer / HostObservation / DhcpScope / …
    settings.py   ключи настроек и сборка подключений
    lib/
        ldap_client.py  чтение Active Directory (только поиск)
        dhcp_client.py  чтение аренд Windows DHCP через WinRM (только Get-*)
        inventory.py    слияние данных в собственную базу и история изменений
        classify.py     что за узел: станция, сервер, сетевое оборудование
        ipaddr.py       разбор адресов, MAC и имён
    templates/assets/  страницы сервиса и его боковая навигация
"""
from . import models  # noqa: F401 — модели должны быть видны SQLAlchemy
from .routes import assets_bp

__all__ = ["assets_bp", "models"]
