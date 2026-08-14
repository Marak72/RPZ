"""Разбор сетевых адресов: IP, MAC, имена узлов.

Вынесено отдельно, потому что этим пользуются все части сервиса: и разбор
ответа DHCP, и поиск по строке, которую ввёл аналитик, и сортировка списка.

Адреса хранятся в базе строкой, но сортировать и сравнивать их как строки
нельзя: «10.10.9.1» окажется больше «10.10.10.1». Поэтому рядом со строкой
всегда лежит числовое представление ``ip_int`` — по нему и идут сортировка и
проверка попадания в диапазон области DHCP.
"""
from __future__ import annotations

import ipaddress
import re

#: MAC в любом привычном виде: 00:11:22:33:44:55, 00-11-22-33-44-55,
#: 001122334455. Windows DHCP отдаёт средний вариант.
_MAC_CHARS = re.compile(r"[^0-9a-fA-F]")
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$")


def parse_ip(value: str) -> str:
    """Привести адрес к каноническому виду или вернуть пустую строку.

    Заодно отсекает мусор вроде «10.10.24.11/26» и «10.10.24.011»: в базе
    должен лежать ровно один вид записи, иначе поиск по точному совпадению
    начнёт промахиваться.
    """
    text = (value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def is_ip(value: str) -> bool:
    return bool(parse_ip(value))


def ip_to_int(value: str) -> int:
    """Числовое представление адреса для сортировки и диапазонов."""
    text = parse_ip(value)
    if not text:
        return 0
    return int(ipaddress.ip_address(text))


def in_range(value: str, start: str, end: str) -> bool:
    """Попадает ли адрес в диапазон области DHCP (границы включительно)."""
    number = ip_to_int(value)
    low, high = ip_to_int(start), ip_to_int(end)
    if not number or not low or not high:
        return False
    return low <= number <= high


def normalize_mac(value: str) -> str:
    """MAC к виду ``aa:bb:cc:dd:ee:ff``.

    Пустую строку возвращаем и для мусора: MAC — справочное поле, и портить
    из-за него запись об адресе не стоит.
    """
    digits = _MAC_CHARS.sub("", value or "").lower()
    if len(digits) != 12:
        return ""
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def looks_like_mac(value: str) -> bool:
    return bool(normalize_mac(value))


def short_name(value: str) -> str:
    """Короткое имя узла: «pc-ivanov» из «pc-ivanov.adm72.local»."""
    name = (value or "").strip().strip(".")
    if not name:
        return ""
    return name.split(".", 1)[0].lower()


def is_hostname(value: str) -> bool:
    """Похожа ли строка на имя узла, а не на адрес или обрывок.

    Нужна для страницы поиска: по одной строке от аналитика надо понять,
    что именно он ввёл, и не гонять лишние запросы.
    """
    text = (value or "").strip().strip(".")
    if not text or is_ip(text) or looks_like_mac(text):
        return False
    return bool(_HOSTNAME_RE.match(text))


def network_of(ip: str, mask: str) -> str:
    """Подсеть в виде ``10.10.24.0/26`` по адресу и маске."""
    address, netmask = parse_ip(ip), parse_ip(mask)
    if not address or not netmask:
        return ""
    try:
        return str(ipaddress.ip_network(f"{address}/{netmask}", strict=False))
    except ValueError:
        return ""
