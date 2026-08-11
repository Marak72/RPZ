"""Разбор файла RPZ-зоны BIND (rpz.block.db) в структурированные записи.

Формат строк зоны, который мы поддерживаем:

    test-bad.example      A   91.200.84.212
    *.test-bad.example    A   91.200.84.212
    browser-sputnik.ru    CNAME rpz-drop.
    *.browser-sputnik.ru  CNAME rpz-drop.

Заголовок зоны ($TTL, SOA с круглыми скобками, NS) пропускается.

Функция parse() — чистая, не зависит от Flask/БД, поэтому легко тестируется.
"""
from dataclasses import dataclass

# Действия RPZ.
ACTION_BLOCK = "block"        # CNAME rpz-drop. / rpz-nxdomain. — домен блокируется
ACTION_REDIRECT = "redirect"  # A <ip> — перенаправление (sinkhole/walled garden)

# Цели CNAME, означающие блокировку (drop/nxdomain), а не реальный редирект.
_BLOCK_TARGETS = {"rpz-drop.", "rpz-nxdomain.", ".", "*."}


@dataclass
class ParsedEntry:
    domain: str          # имя без ведущего "*."
    is_wildcard: bool    # была ли это запись "*.domain"
    record_type: str     # A / CNAME
    target: str          # rpz-drop. или IP-адрес
    action: str          # block / redirect


def _is_header_line(stripped: str) -> bool:
    """Определить служебные строки заголовка зоны, которые нужно пропустить."""
    if not stripped or stripped.startswith(";"):
        return True
    upper = stripped.upper()
    if upper.startswith("$"):  # $TTL, $ORIGIN
        return True
    if stripped.startswith("@"):  # начало SOA
        return True
    if "SOA" in upper or " NS " in f" {upper} " or upper.endswith(" NS"):
        return True
    if "NS " in upper and "CNAME" not in upper and " A " not in f" {upper} ":
        # строка вида "    IN  NS  localhost."
        if "NS" in upper.split():
            return True
    # строки внутри SOA: только числа, возможно со скобками и суффиксами H/M/W/D
    body = stripped.strip("()")
    tokens = body.split()
    if tokens and all(_looks_like_soa_token(t) for t in tokens):
        return True
    if stripped in (")", "("):
        return True
    return False


def _looks_like_soa_token(token: str) -> bool:
    token = token.strip("()")
    if not token:
        return True
    # 2026012302  или  1H / 15M / 1W / 1D
    if token.isdigit():
        return True
    if token[:-1].isdigit() and token[-1].upper() in {"H", "M", "W", "D", "S"}:
        return True
    return False


def parse(text: str) -> list[ParsedEntry]:
    """Разобрать текст файла зоны в список записей блокировки."""
    entries: list[ParsedEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if _is_header_line(line):
            continue

        # Отбросить комментарий в конце строки.
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        if not line:
            continue

        tokens = line.split()
        if len(tokens) < 2:
            continue

        name = tokens[0]
        rest = tokens[1:]
        # Необязательный класс IN перед типом записи.
        if rest and rest[0].upper() == "IN":
            rest = rest[1:]
        if len(rest) < 2:
            continue

        record_type = rest[0].upper()
        if record_type not in ("A", "CNAME"):
            continue
        target = rest[1]

        is_wildcard = name.startswith("*.")
        domain = name[2:] if is_wildcard else name
        domain = domain.rstrip(".").lower()
        if not domain:
            continue

        if record_type == "CNAME":
            action = ACTION_BLOCK if target.lower() in _BLOCK_TARGETS else ACTION_REDIRECT
        else:  # A-запись — перенаправление на IP
            action = ACTION_REDIRECT

        entries.append(
            ParsedEntry(
                domain=domain,
                is_wildcard=is_wildcard,
                record_type=record_type,
                target=target,
                action=action,
            )
        )
    return entries


def group_by_domain(entries: list[ParsedEntry]) -> list[dict]:
    """Свернуть base+wildcard одного домена в одну строку для отображения."""
    grouped: dict[str, dict] = {}
    for e in entries:
        row = grouped.get(e.domain)
        if row is None:
            row = {
                "domain": e.domain,
                "record_type": e.record_type,
                "target": e.target,
                "action": e.action,
                "has_wildcard": False,
                "has_base": False,
            }
            grouped[e.domain] = row
        if e.is_wildcard:
            row["has_wildcard"] = True
        else:
            row["has_base"] = True
    return sorted(grouped.values(), key=lambda r: r["domain"])
