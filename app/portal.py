"""Реестр сервисов портала.

Портал — это одна точка входа с общими пользователями, темой и версткой,
внутри которой живут независимые сервисы (вкладки верхнего уровня):

  * ``fstec``  (``/fstec/``)  — блокировка доменов из писем ФСТЭК через RPZ BIND;
  * ``skydns`` (``/skydns/``) — угрозы из статистики SkyDNS и поиск конечных
    хостов в MaxPatrol SIEM;
  * ``tasks``  (``/tasks/``)  — задачи отдела: доска, карточки, комментарии.

В корне портала (``/``) — главная страница со списком сервисов, blueprint
``hub``. Снаружи всё это отдаётся на подпути ``/soc/``, то есть сервисы
открываются как ``/soc/fstec/`` и ``/soc/skydns/``.

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
        endpoint="fstec.dashboard",
        blueprint="fstec",
        nav_template="fstec/nav.html",
    ),
    Service(
        id="tasks",
        title="Задачи отдела",
        subtitle="кто что делает",
        icon="list",
        endpoint="tasks.board",
        blueprint="tasks",
        nav_template="tasks/nav.html",
    ),
    Service(
        id="skydns",
        title="Угрозы SkyDNS",
        subtitle="кто ходит на вредоносные ресурсы",
        icon="activity",
        endpoint="skydns.dashboard",
        blueprint="skydns",
        nav_template="skydns/nav.html",
    ),
)

# Главная портала — не сервис: у неё нет своей боковой навигации, поэтому она
# описана отдельно и в переключателе стоит над списком сервисов.
HUB = Service(
    id="hub",
    title="Главная",
    subtitle="отдел противодействия кибератакам",
    icon="grid",
    endpoint="hub.index",
    blueprint="hub",
    nav_template="nav/_hub.html",
)

DEFAULT_SERVICE = HUB


def service_by_blueprint(blueprint: str | None) -> Service:
    """Активный сервис по имени blueprint текущего запроса."""
    for service in SERVICES:
        if service.blueprint == blueprint:
            return service
    return HUB
