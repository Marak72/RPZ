"""Правила «этот домен вредоносным не считать».

Категории SkyDNS срабатывают не только на угрозы: в ту же выборку попадают
телеметрия, обновления и CDN-имена вида ``si21if1u2.afd.footprintdns.com``.
Разбирать их поштучно бессмысленно — завтра приедет ещё сотня таких же имён,
поэтому оператор заводит правило, а не отметку на записи.

Правило работает в обе стороны: вперёд (домен не попадает в список при
следующей выгрузке) и назад (уже загруженные совпавшие записи убираются
сразу при сохранении правила).
"""
from __future__ import annotations

from ..extensions import db
from ..models import DomainExclusion, ThreatDomain
from . import domains as dm


def patterns() -> list[str]:
    """Все действующие правила."""
    return [row.pattern for row in DomainExclusion.query.all()]


class Matcher:
    """Проверка доменов по всем правилам разом.

    Правила читаются один раз: выгрузка прогоняет через них тысячи имён, и
    ходить в базу на каждое — впустую.
    """

    def __init__(self, rules: list[str] | None = None) -> None:
        self.rules = rules if rules is not None else patterns()
        self.hits: dict[str, int] = {}

    def excluded(self, domain: str) -> str:
        """Правило, под которое подошёл домен (или пустая строка)."""
        pattern = dm.matches_any(self.rules, domain)
        if pattern:
            self.hits[pattern] = self.hits.get(pattern, 0) + 1
        return pattern

    def save_hits(self) -> None:
        """Записать, сколько раз каждое правило сработало.

        Счётчик отвечает на вопрос «правило ещё нужно?»: если за месяцы ноль
        срабатываний, его можно убрать.
        """
        if not self.hits:
            return
        rows = DomainExclusion.query.filter(
            DomainExclusion.pattern.in_(list(self.hits))
        ).all()
        for row in rows:
            row.hits_count = (row.hits_count or 0) + self.hits[row.pattern]


def matching_threats(pattern: str) -> list[ThreatDomain]:
    """Уже загруженные домены, попадающие под правило.

    Сравнение идёт в Python, а не запросом LIKE: правило про поддомены
    должно совпадать по границе метки, иначе ``*.footprintdns.com`` поймал
    бы ещё и ``evilfootprintdns.com``.
    """
    if pattern.startswith("*."):
        base = dm.normalize(pattern)
        candidates = ThreatDomain.query.filter(
            db.or_(ThreatDomain.domain == base,
                   ThreatDomain.domain.like("%." + base))
        ).all()
    else:
        candidates = ThreatDomain.query.filter_by(
            domain=dm.normalize(pattern)
        ).all()
    return [t for t in candidates if dm.matches(pattern, t.domain)]


def apply_rule(rule: DomainExclusion) -> int:
    """Убрать уже загруженные домены, подошедшие под новое правило."""
    victims = matching_threats(rule.pattern)
    for threat in victims:
        db.session.delete(threat)
    rule.removed_count = len(victims)
    return len(victims)
