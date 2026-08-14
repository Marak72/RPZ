"""Определение, что за узел скрывается за адресом.

Зачем. Далеко не каждый адрес, попавший в разбор, принадлежит рабочей
станции. В статистику SkyDNS и SIEM регулярно приезжают адреса шлюзов и
DNS-форвардеров площадок: события DNS группируются по источнику запроса, а
для площадки с собственным форвардером источником окажется он сам, а не
машина сотрудника. Искать за таким адресом человека бессмысленно — там его
нет, и сервис должен сказать об этом прямо, а не изображать находку.

Как. Сначала смотрим на операционную систему из AD — это самый надёжный
признак. Если объекта в каталоге нет (сетевое оборудование в домен не
заводят), разбираем имя из аренды DHCP по принятым в организации приставкам.
Правила намеренно лежат таблицей: их дополняют по мере того, как в сети
появляются новые соглашения об именах.
"""
from __future__ import annotations

import re

KIND_WORKSTATION = "workstation"
KIND_SERVER = "server"
KIND_DC = "dc"
KIND_NETWORK = "network"
KIND_PRINTER = "printer"
KIND_UNKNOWN = "unknown"

#: Подпись и оформление значка для интерфейса.
KIND_TITLES = {
    KIND_WORKSTATION: "Рабочая станция",
    KIND_SERVER: "Сервер",
    KIND_DC: "Контроллер домена",
    KIND_NETWORK: "Сетевой узел",
    KIND_PRINTER: "Принтер",
    KIND_UNKNOWN: "Неизвестно",
}

KIND_BADGES = {
    KIND_WORKSTATION: "badge--info",
    KIND_SERVER: "badge--warning",
    KIND_DC: "badge--danger",
    KIND_NETWORK: "badge--neutral",
    KIND_PRINTER: "badge--neutral",
    KIND_UNKNOWN: "badge--neutral",
}

#: Узлы, за которыми не сидит человек: показывать «кто это» бесполезно.
INFRASTRUCTURE_KINDS = (KIND_NETWORK, KIND_DC)

#: Приставки и куски имени → вид узла. Порядок важен: первое совпадение
#: выигрывает, поэтому более узкие правила стоят выше общих.
NAME_RULES: tuple[tuple[str, str], ...] = (
    (r"^dc\d*[-_]", KIND_DC),
    (r"^(ns|dns)\d*[-_.]", KIND_NETWORK),
    (r"[-_](gw|gate|router|rtr)\d*([-_.]|$)", KIND_NETWORK),
    (r"^(gw|gate|router|rtr|rt)\d*[-_.]", KIND_NETWORK),
    (r"^(sw|switch|cisco|mikrotik|dlink|zyxel|huawei)\d*[-_.]", KIND_NETWORK),
    (r"^(fw|firewall|utm|ideco|vipnet|continent|scada)\d*[-_.]", KIND_NETWORK),
    (r"^(cam|camera|video|nvr|dvr)\d*[-_.]", KIND_NETWORK),
    (r"^(prn|print|printer|hp|kyocera|xerox)\d*[-_.]", KIND_PRINTER),
    (r"^(srv|server|s)\d*[-_]", KIND_SERVER),
    (r"^(pc|ws|arm|nb|note|comp|kompyuter)\d*[-_]", KIND_WORKSTATION),
)

_COMPILED = tuple((re.compile(pattern), kind) for pattern, kind in NAME_RULES)

#: Признаки серверной ОС в строке operatingSystem.
_SERVER_OS = ("server", "сервер", "hyper-v", "esxi")
#: Признаки клиентской ОС.
_CLIENT_OS = ("windows 7", "windows 8", "windows 10", "windows 11",
              "windows xp", "windows vista", "astra", "alt ", "ubuntu",
              "linux mint", "рэд ос", "red os")


def classify(name: str = "", os_name: str = "", dn: str = "") -> str:
    """Вид узла по имени, операционной системе и месту в каталоге."""
    system = (os_name or "").lower()
    place = (dn or "").lower()

    # Контроллеры домена лежат в отдельном подразделении — это надёжнее имени.
    if "ou=domain controllers" in place:
        return KIND_DC
    if system:
        if any(token in system for token in _SERVER_OS):
            return KIND_SERVER
        if any(token in system for token in _CLIENT_OS):
            return KIND_WORKSTATION

    short = (name or "").strip().lower().split(".", 1)[0]
    if short:
        for pattern, kind in _COMPILED:
            if pattern.search(short):
                return kind
    return KIND_UNKNOWN


def title(kind: str) -> str:
    return KIND_TITLES.get(kind, KIND_TITLES[KIND_UNKNOWN])


def badge(kind: str) -> str:
    return KIND_BADGES.get(kind, "badge--neutral")


def is_infrastructure(kind: str) -> bool:
    """Узел, за которым не сидит сотрудник."""
    return kind in INFRASTRUCTURE_KINDS
