"""Реестр сервисов портала.

Портал — это одна точка входа с общими пользователями, темой и версткой,
внутри которой живут независимые сервисы (вкладки верхнего уровня):

  * ``fstec``  — блокировка доменов из писем ФСТЭК через RPZ-зону BIND;
  * ``skydns`` — угрозы из статистики SkyDNS и поиск конечных хостов в SIEM.

Каждый сервис — отдельный blueprint со своим набором страниц. Здесь описано
только то, что нужно общей вёрстке: заголовок вкладки, иконка, точка входа и
имя частичного шаблона с боковой навигацией сервиса.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    id: str
    title: str
    subtitle: str
    icon: str
    endpoint: str          # точка входа сервиса (для url_for)
    blueprint: str         # имя blueprint — по нему определяется активная вкладка
    nav_template: str      # частичный шаблон боковой навигации


SERVICES: tuple[Service, ...] = (
    Service(
        id="fstec",
        title="РПЗ ФСТЭК",
        subtitle="блокировка доменов",
        icon="shield",
        endpoint="main.dashboard",
        blueprint="main",
        nav_template="nav/_fstec.html",
    ),
    Service(
        id="skydns",
        title="Угрозы SkyDNS",
        subtitle="кто ходит на вредоносные ресурсы",
        icon="activity",
        endpoint="skydns.dashboard",
        blueprint="skydns",
        nav_template="nav/_skydns.html",
    ),
)

DEFAULT_SERVICE = SERVICES[0]


def service_by_blueprint(blueprint: str | None) -> Service:
    """Активный сервис по имени blueprint текущего запроса."""
    for service in SERVICES:
        if service.blueprint == blueprint:
            return service
    return DEFAULT_SERVICE
