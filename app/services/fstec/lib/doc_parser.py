"""Извлечение индикаторов компрометации из писем ФСТЭК (.docx / .odt).

В письмах ФСТЭК индикаторы для блокировки приводятся каждый на отдельной строке
(заканчивается «;» или «.»), часто в замаскированном виде (defang):
example[.]com, hxxp[:]//..., 5[.]252[.]153[.]67. Имена вложений, названия ПО и
ссылки-источники сидят внутри обычных предложений — их брать не нужно.

Поэтому индикаторы извлекаются только из сегментов, которые ЦЕЛИКОМ являются
доменом / IP / URL / хешем. Дополнительно из любого места текста вытягиваются
адреса электронной почты.

Типы записей (entry_type):
  domain  — домен, пригоден для блокировки в RPZ
  ip      — IPv4-адрес (блокируется на межсетевом экране, не в RPZ)
  url     — ссылка С ПУТЁМ; в RPZ блокировать путь нельзя, поэтому такие
            индикаторы выделяются отдельно. Хост из такой ссылки доменом НЕ
            становится: вредоносна страница, а не сайт целиком (github.com,
            telegram.me и подобные), а RPZ закрывает имя целиком
  email   — адрес отправителя. Домен из адреса доменом-кандидатом тоже НЕ
            становится — по той же причине: фишинг шлют с mail.ru и gmail.com,
            и блокировка такого домена закрыла бы отделу почту целиком
  sha256 / sha1 / md5 — хеши-индикаторы для систем мониторинга

Функции работают со строкой текста, поэтому их легко тестировать без файлов.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

# --- Регулярные выражения -------------------------------------------------

_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
# TLD: обычный буквенный (.com, .ru) либо punycode для IDN (.xn--p1ai = .рф).
_TLD_PATTERN = r"(?:xn--[a-z0-9-]{2,}|[a-z]{2,})"
_DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+" + _TLD_PATTERN, re.IGNORECASE
)
_EMAIL_RE = re.compile(
    r"([a-z0-9._%+-]+)@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    + _TLD_PATTERN + r")",
    re.IGNORECASE,
)
# Одиночный индикатор внутри предложения после слова «адрес» (адресу/адреса/…),
# напр.: «к IP-адресу 31[.]56[.]209[.]126,» или «к адресу crystalxrat[.]net,».
_INLINE_ADDR_RE = re.compile(r"адрес[ауе]?\s+(\S+)", re.IGNORECASE)

# Хеши: проверяем от длинного к короткому (64 → 40 → 32).
_HASH_TYPES = (("sha256", 64), ("sha1", 40), ("md5", 32))
_HEX_RE = re.compile(r"[0-9a-f]+", re.IGNORECASE)

# Легитимные домены, встречающиеся в письмах как ссылки-источники.
_ALLOWLIST = {"fstec.ru", "bdu.fstec.ru", "gov.ru", "cert.gov.ru"}

# Расширения файлов — чтобы имя вложения не приняли за домен.
# «com» намеренно НЕ включаем: это настоящий TLD.
_FILE_EXTENSIONS = {
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk",
    "msi", "cab", "iso", "img", "jar", "apk", "bin", "sys", "tmp", "log",
    "rar", "zip", "7z", "gz", "bz", "bz2", "tar", "tgz", "arj", "ace",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf",
    "txt", "csv", "odt", "ods", "xml", "html", "htm", "php", "asp", "aspx",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp",
    "mp3", "mp4", "avi", "mkv", "wav", "torrent", "eml", "msg", "pst",
    "conf", "cfg", "ini", "json", "yml", "yaml", "sql", "db", "bak",
}

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63


@dataclass
class ExtractedEntry:
    value: str
    entry_type: str  # domain / ip / url / email / sha256 / sha1 / md5
    host: str = ""   # для url и email — извлечённый домен
    # Строка документа, из которой индикатор взят, — как она там написана,
    # до снятия маскировки. Нужна для писем в PDF: там текст восстанавливается
    # из глифов, и сверить извлечённое значение с исходной строкой — часто
    # единственный способ заметить подмену похожего символа.
    context: str = ""


# --- Нормализация (refang) ------------------------------------------------

def refang(text: str) -> str:
    """Убрать типовую маскировку индикаторов."""
    text = text.replace("(.)", ".").replace("{.}", ".")
    text = re.sub(r"\s*\[\.\]\s*", ".", text)  # "example [.] com" / "a[.]b"
    text = text.replace("[:]", ":").replace("(:)", ":")
    text = re.sub(r"\bhxxps\b", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhxxp\b", "http", text, flags=re.IGNORECASE)
    return text


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_valid_domain(value: str) -> bool:
    """Строгая проверка домена — отсекает имена файлов и мусор."""
    if not value or len(value) > MAX_DOMAIN_LENGTH:
        return False
    if not _DOMAIN_RE.fullmatch(value):
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if any(not lb or len(lb) > MAX_LABEL_LENGTH for lb in labels):
        return False
    if any(lb.startswith("-") or lb.endswith("-") for lb in labels):
        return False
    tld = labels[-1].lower()
    if not (2 <= len(tld) <= 24):
        return False
    # TLD — либо только буквы (.com, .ru), либо punycode для IDN (.xn--p1ai = .рф).
    is_punycode = tld.startswith("xn--") and tld[4:].isalnum()
    if not tld.isalpha() and not is_punycode:
        return False
    if tld in _FILE_EXTENSIONS:
        return False
    return True


def _normalize_domain(value: str) -> str:
    value = value.strip().strip(".").lower()
    if value.startswith("www."):
        value = value[4:]
    return value


def _clean_segment(seg: str) -> str:
    """Снять пробелы, обрамляющие кавычки/скобки и хвостовую пунктуацию."""
    seg = seg.strip().strip("«»\"'()[]<>")
    seg = seg.strip().rstrip(".,;:")
    return seg.strip()


def _parse_url(seg: str):
    """Разобрать URL. Возвращает (host, has_path, нормализованный URL) или None."""
    candidate = seg if "://" in seg else "http://" + seg
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if not host or not is_valid_domain(host):
        return None
    path = parsed.path or ""
    has_path = bool(path.strip("/")) or bool(parsed.query) or bool(parsed.fragment)
    normalized = urlunparse(
        (parsed.scheme or "http", parsed.netloc.lower(), path,
         parsed.params, parsed.query, parsed.fragment)
    )
    return host, has_path, normalized


def _classify_segment(seg: str) -> list[ExtractedEntry]:
    """Классифицировать сегмент, если он ЦЕЛИКОМ является индикатором."""
    if not seg:
        return []

    # URL (со схемой либо явным путём после домена).
    looks_like_url = "://" in seg or (
        "/" in seg and _DOMAIN_RE.match(seg.split("/", 1)[0])
    )
    if looks_like_url:
        parsed = _parse_url(seg)
        if not parsed:
            return []
        host, has_path, normalized = parsed

        if has_path:
            # Только сама ссылка — хост кандидатом на блокировку НЕ становится.
            #
            # Вредоносной в такой строке является страница, а не сайт целиком:
            # в письмах ФСТЭК регулярно встречаются github.com/<аккаунт>/…,
            # telegram.me/<канал>, диски и файлопомойки. RPZ блокирует имя
            # целиком, поэтому выгрузка такого хоста закрыла бы отделу весь
            # легитимный сервис.
            #
            # Если домен и правда вредоносен целиком, в письме он приводится
            # отдельной строкой (как voffice.help) — и тогда попадёт в домены
            # оттуда. Либо аналитик добавит его вручную, увидев хост в разделе
            # «URL с путями».
            return [ExtractedEntry(value=normalized, entry_type="url", host=host)]

        if host in _ALLOWLIST:
            return []
        return [ExtractedEntry(value=host, entry_type="domain")]

    # IPv4 целиком.
    if _IPV4_RE.fullmatch(seg):
        return [ExtractedEntry(value=seg, entry_type="ip")] if _valid_ipv4(seg) else []

    # Хеш целиком (hex фиксированной длины).
    if _HEX_RE.fullmatch(seg):
        for htype, length in _HASH_TYPES:
            if len(seg) == length:
                return [ExtractedEntry(value=seg.lower(), entry_type=htype)]
        return []

    # Домен целиком.
    value = _normalize_domain(seg)
    if is_valid_domain(value) and value not in _ALLOWLIST:
        return [ExtractedEntry(value=value, entry_type="domain")]

    return []


def unparsed_candidates(text: str) -> list[tuple[str, str]]:
    """Строки, которые выглядят как индикатор, но проверку не прошли.

    Зачем это нужно. Разбор устроен строго: всё, что не является доменом, IP,
    ссылкой или хешем, отбрасывается — иначе в кандидаты уехали бы имена
    вложений и куски предложений. Но для писем в PDF строгость оборачивается
    против нас: подмена символа делает индикатор невалидным, и он пропадает
    молча. Домен ``gоogle-drive.net`` с кириллической «о» не пройдёт проверку
    доменного имени, хеш с буквой ``g`` — проверку шестнадцатеричной строки.
    Аналитик при этом даже не узнает, что строка была.

    Поэтому такие сегменты собираются отдельно и показываются как «не
    распознано». Автоматически их не исправить — угадать исходный символ
    нельзя, — но человек, увидев строку письма, поймёт всё за секунду.

    Возвращает пары «сегмент, чем он похож на индикатор».
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    for line in refang(text).splitlines():
        for raw in line.split(";"):
            seg = _clean_segment(raw)
            if not seg or len(seg) > 400 or seg in seen:
                continue
            if _classify_segment(seg):
                continue          # разобралось — вопросов нет
            if " " in seg or "\t" in seg:
                continue          # это предложение, а не индикатор

            reason = _looks_like_indicator(seg)
            if reason:
                seen.add(seg)
                out.append((seg, reason))
    return out


def _looks_like_indicator(seg: str) -> str:
    """Чем сегмент похож на индикатор. Пустая строка — ничем."""
    letters_and_digits = sum(ch.isalnum() for ch in seg)
    if letters_and_digits < 4:
        return ""

    # Похоже на хеш: длина рядом с известной и почти весь состав — hex.
    compact = seg.strip()
    if 28 <= len(compact) <= 70 and not compact.count("."):
        hexish = sum(ch in "0123456789abcdefABCDEF" for ch in compact)
        if hexish >= len(compact) - 3:
            return "похоже на хеш, но есть символы вне 0-9 и a-f"

    # Похоже на доменное имя: есть точка, нет пробелов, разумная длина.
    if "." in compact and 4 <= len(compact) <= MAX_DOMAIN_LENGTH:
        tail = compact.rsplit(".", 1)[-1]
        if 2 <= len(tail) <= 24 and tail.lower() not in _FILE_EXTENSIONS:
            if any(not ch.isascii() for ch in compact):
                return "похоже на домен, но записан не латиницей"
            return "похоже на домен, но не прошёл проверку имени"
    return ""


def _attach_context(entries: list[ExtractedEntry], original: str) -> None:
    """Приписать каждому индикатору строку документа, где он встретился.

    Ищем по исходному тексту, а не по обработанному: аналитику нужна строка
    ровно в том виде, в каком она в письме, вместе с маскировкой. Сопоставляем
    по обработанной копии строки — маскировка иначе не даст совпасть.
    """
    lines = original.splitlines()
    refanged = [refang(line).lower() for line in lines]
    for entry in entries:
        if entry.context:
            continue
        needle = entry.value.lower()
        for index, line in enumerate(refanged):
            if needle in line:
                entry.context = lines[index].strip()[:300]
                break


def extract(text: str) -> list[ExtractedEntry]:
    """Извлечь уникальные индикаторы (домены, IP, URL, почту, хеши)."""
    original = text
    text = refang(text)
    seen: set[str] = set()
    result: list[ExtractedEntry] = []

    def _add_many(entries: list[ExtractedEntry]) -> None:
        for entry in entries:
            if entry.value not in seen:
                seen.add(entry.value)
                result.append(entry)

    # Индикаторы из «строк-индикаторов»: строка → сегменты по ';' → классификация.
    for line in text.splitlines():
        for raw_seg in line.split(";"):
            _add_many(_classify_segment(_clean_segment(raw_seg)))

    # Одиночные индикаторы внутри предложений после слова «адрес».
    for m in _INLINE_ADDR_RE.finditer(text):
        _add_many(_classify_segment(_clean_segment(m.group(1))))

    # Адреса электронной почты. В блокировку уходит сам адрес, а не домен из
    # него: с mail.ru или gmail.com рассылают фишинг, но закрыть эти сервисы
    # отделу — куда больший ущерб, чем сама рассылка. Домен, вредоносный
    # целиком, в письме приводится отдельной строкой и попадёт в кандидаты
    # оттуда; иначе аналитик добавит его вручную, увидев хост рядом с адресом.
    for match in _EMAIL_RE.finditer(text):
        host = _normalize_domain(match.group(2))
        if not is_valid_domain(host):
            continue
        address = (match.group(1) + "@" + host).lower()
        _add_many([ExtractedEntry(value=address, entry_type="email",
                                  host=host)])

    _attach_context(result, original)
    return result


# --- Чтение текста из документов ------------------------------------------

def _text_from_docx(data: bytes) -> str:
    from docx import Document as DocxDocument

    doc = DocxDocument(io.BytesIO(data))
    parts: list[str] = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                parts.append(cell.text)
    return "\n".join(parts)


def _text_from_odt(data: bytes) -> str:
    from odf import teletype, text as odf_text
    from odf.opendocument import load

    doc = load(io.BytesIO(data))
    parts: list[str] = []
    for element in doc.getElementsByType(odf_text.P):
        parts.append(teletype.extractText(element))
    for element in doc.getElementsByType(odf_text.H):
        parts.append(teletype.extractText(element))
    return "\n".join(parts)


class MissingDependency(ValueError):
    """Не установлена библиотека, нужная для разбора этого формата."""


def _text_from_pdf(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pypdf не обязателен: без него PDF только хранится
        raise MissingDependency(
            "Для распознавания индикаторов из PDF нужна библиотека pypdf "
            "(pip install pypdf). Само письмо при этом сохраняется и открывается."
        ) from exc

    reader = PdfReader(io.BytesIO(data))
    parts: list[str] = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001 — повреждённая страница не должна ронять разбор
            continue
    text = "\n".join(parts)
    # В PDF индикаторы часто переносятся: «example[.]co\nm». Склеиваем переносы
    # внутри слова, но сохраняем разбиение на строки-индикаторы.
    text = re.sub(r"-\n(?=\w)", "", text)
    return text


def extract_text_from_file(filename: str, data: bytes) -> str:
    """Достать текст из письма (.docx / .odt / .pdf)."""
    lower = (filename or "").lower()
    if not data:
        raise ValueError("Файл пустой.")
    if lower.endswith(".docx"):
        return _text_from_docx(data)
    if lower.endswith(".odt"):
        return _text_from_odt(data)
    if lower.endswith(".pdf"):
        return _text_from_pdf(data)
    raise ValueError("Поддерживаются файлы .docx, .odt и .pdf")


def extract_from_file(filename: str, data: bytes) -> list[ExtractedEntry]:
    """Извлечь индикаторы из загруженного файла по его расширению."""
    return extract(extract_text_from_file(filename, data))
