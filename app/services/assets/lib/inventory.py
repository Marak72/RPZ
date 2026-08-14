"""Слияние сведений из DHCP и AD в собственную базу узлов.

Здесь живёт вся логика «что считать изменением». Она вынесена из маршрутов и
фоновых заданий по одной причине: это единственное место, где принимаются
решения о содержимом базы, и его нужно уметь проверить тестами без сети.

Главное правило: **запись в историю только при настоящем изменении.** Выгрузка
идёт по расписанию и приносит одно и то же; если писать наблюдение каждый раз,
история за месяц превратится в сто тысяч одинаковых строк, и найти в ней
реальную смену владельца адреса станет невозможно.
"""
from __future__ import annotations

from datetime import datetime

from ....core.extensions import db
from ..models import (
    SOURCE_AD,
    SOURCE_DHCP,
    AdComputer,
    DhcpScope,
    HostObservation,
    NetworkHost,
)
from . import classify
from .ipaddr import ip_to_int, normalize_mac, parse_ip, short_name


def _changes(host: NetworkHost, hostname: str, mac: str, state: str) -> str:
    """Человеческое описание того, что поменялось у адреса.

    Пустая строка означает «ничего не изменилось» — наблюдение не пишем.
    """
    parts = []
    if hostname and short_name(hostname) != short_name(host.hostname):
        parts.append("имя: %s → %s" % (host.hostname or "—", hostname))
    if mac and mac != host.mac:
        parts.append("MAC: %s → %s" % (host.mac or "—", mac))
    if state and state != host.lease_state:
        parts.append("аренда: %s → %s" % (host.lease_state or "—", state))
    return "; ".join(parts)


def upsert_lease(lease, *, source: str = SOURCE_DHCP,
                 seen_at: datetime | None = None) -> tuple[NetworkHost, bool]:
    """Занести аренду в базу. Возвращает (запись, создана ли она заново)."""
    ip = parse_ip(lease.ip)
    if not ip:
        raise ValueError("Аренда без разбираемого адреса: %r" % (lease.ip,))

    now = seen_at or datetime.utcnow()
    hostname = short_name(lease.hostname)
    mac = normalize_mac(lease.mac)
    state = (lease.state or "").strip()

    host = NetworkHost.query.filter_by(ip=ip).first()
    created = host is None
    if created:
        host = NetworkHost(ip=ip, first_seen=now, source=source)
        db.session.add(host)
    else:
        # Первое наблюдение существующей записи фиксируем до перезаписи полей.
        change = _changes(host, hostname, mac, state)
        if change:
            db.session.add(HostObservation(
                host=host, seen_at=now, hostname=hostname, mac=mac,
                lease_state=state, change=change,
            ))

    host.ip_int = ip_to_int(ip)
    if hostname:
        # Сменилось имя — значит адрес занят уже другой машиной, и прежняя
        # связь с объектом AD стала ложной. Не оборвав её, карточка показывала
        # бы описание и подразделение чужого компьютера: имя из аренды новое,
        # а всё остальное — от предыдущего владельца адреса.
        if host.ad_computer is not None and host.ad_computer.name != hostname:
            host.ad_computer = None
        host.hostname = hostname
    if mac:
        host.mac = mac
    host.lease_state = state
    host.lease_expires_at = lease.expires_at
    host.dhcp_server = (lease.server or "")[:255]
    host.scope_id = parse_ip(lease.scope_id or "")
    host.last_seen = now
    if created:
        db.session.add(HostObservation(
            host=host, seen_at=now, hostname=hostname, mac=mac,
            lease_state=state, change="адрес добавлен в базу",
        ))
    _reclassify(host)
    return host, created


def upsert_computer(computer, *, seen_at: datetime | None = None
                    ) -> tuple[AdComputer, bool]:
    """Занести объект компьютера из AD."""
    name = short_name(computer.name or computer.fqdn)
    if not name:
        raise ValueError("Объект компьютера без имени")

    now = seen_at or datetime.utcnow()
    row = AdComputer.query.filter_by(name=name).first()
    created = row is None
    if created:
        row = AdComputer(name=name)
        db.session.add(row)

    row.fqdn = (computer.fqdn or "").lower()
    row.dn = computer.dn or ""
    row.ou_path = computer.ou_path[:500]
    row.description = (computer.description or "")[:1000]
    row.os = (computer.os or "")[:255]
    row.os_version = (computer.os_version or "")[:100]
    row.enabled = bool(computer.enabled)
    row.managed_by = computer.managed_by or ""
    row.last_logon = computer.last_logon
    row.when_created = computer.when_created
    row.kind = classify.classify(name=name, os_name=row.os, dn=row.dn)
    row.synced_at = now
    return row, created


def link_host(host: NetworkHost) -> bool:
    """Связать адрес с объектом AD по имени. True, если связь появилась."""
    name = short_name(host.hostname)
    if not name:
        return False
    if host.ad_computer is not None and host.ad_computer.name == name:
        return False
    computer = AdComputer.query.filter_by(name=name).first()
    if computer is None:
        return False
    host.ad_computer = computer
    _reclassify(host)
    return True


def link_all() -> int:
    """Связать все несвязанные адреса с объектами AD.

    Выполняется после выгрузки AD: аренда могла появиться раньше, чем в
    каталоге завели машину, и наоборот.
    """
    linked = 0
    hosts = NetworkHost.query.filter(NetworkHost.hostname != "").all()
    for host in hosts:
        if link_host(host):
            linked += 1
    return linked


def _reclassify(host: NetworkHost) -> None:
    """Пересчитать вид узла: данные AD надёжнее имени из аренды."""
    computer = host.ad_computer
    host.kind = classify.classify(
        name=host.hostname or (computer.name if computer else ""),
        os_name=computer.os if computer else "",
        dn=computer.dn if computer else "",
    )


def upsert_scope(server: str, scope, *, lease_count: int = 0,
                 seen_at: datetime | None = None) -> tuple[DhcpScope, bool]:
    """Занести область DHCP."""
    now = seen_at or datetime.utcnow()
    row = DhcpScope.query.filter_by(server=server, scope_id=scope.scope_id).first()
    created = row is None
    if created:
        row = DhcpScope(server=server, scope_id=scope.scope_id)
        db.session.add(row)
    row.name = (scope.name or "")[:255]
    row.mask = scope.mask or ""
    row.start_ip = scope.start or ""
    row.end_ip = scope.end or ""
    row.touch_range()
    row.state = (scope.state or "")[:40]
    if lease_count:
        row.lease_count = lease_count
    row.synced_at = now
    return row, created


def server_for_ip(ip: str) -> str:
    """Какой DHCP-сервер отвечает за этот адрес.

    Пустая строка означает, что адрес не попадает ни в одну известную область
    — например, он статический. Тогда точечная проверка в DHCP смысла не
    имеет, и это надо сказать оператору, а не опрашивать все площадки.
    """
    number = ip_to_int(ip)
    if not number:
        return ""
    scope = (
        DhcpScope.query
        .filter(DhcpScope.start_int <= number, DhcpScope.end_int >= number)
        .order_by(DhcpScope.start_int.desc())
        .first()
    )
    return scope.server if scope else ""


def scope_for_ip(ip: str) -> DhcpScope | None:
    number = ip_to_int(ip)
    if not number:
        return None
    return (
        DhcpScope.query
        .filter(DhcpScope.start_int <= number, DhcpScope.end_int >= number)
        .order_by(DhcpScope.start_int.desc())
        .first()
    )


def ensure_host(ip: str, *, source: str = SOURCE_AD) -> NetworkHost:
    """Получить запись адреса, заведя её при необходимости."""
    clean = parse_ip(ip)
    if not clean:
        raise ValueError("Недопустимый адрес: %r" % (ip,))
    host = NetworkHost.query.filter_by(ip=clean).first()
    if host is None:
        now = datetime.utcnow()
        host = NetworkHost(ip=clean, ip_int=ip_to_int(clean), source=source,
                           first_seen=now, last_seen=now)
        db.session.add(host)
    return host
