"""Извлечение индикаторов компрометации из писем ФСТЭК (.docx / .odt).

В письмах ФСТЭК индикаторы для блокировки приводятся каждый на отдельной строке
(заканчивается «;» или «.»), часто в замаскированном виде (defang):
example[.]com, hxxp[:]//..., 5[.]252[.]153[.]67. Имена вложений, названия ПО и
ссылки-источники сидят внутри обычных предложений — их брать не нужно.

Поэтому индикаторы извлекаются только из сегментов, которые ЦЕЛИКОМ являются
доменом / IP / URL / хешем. Дополнительно из любого места текста вытягивается
домен из e-mail отправителя.

Типы записей (entry_type):
  domain  — домен, пригоден для блокировки в RPZ
  ip      — IPv4-адрес (блокируется на межсетевом экране, не в RPZ)
  url     — ссылка С ПУТЁМ; в RPZ блокировать путь нельзя, поэтому такие
            индикаторы выделяются отдельно (хост при этом попадает в domain)
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
    r"[a-z0-9._%+-]+@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
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
    entry_type: str  # domain / ip / url / sha256 / sha1 / md5
    host: str = ""   # для url — извлечённый хост


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
    """Классифицировать сегмент, если он ЦЕЛИКОМ является индикатором.

    Возвращает список: для URL с путём — сама ссылка И её хост.
    """
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
        out: list[ExtractedEntry] = []
        if has_path:
            out.append(
                ExtractedEntry(value=normalized, entry_type="url", host=host)
            )
        if host not in _ALLOWLIST:
            out.append(ExtractedEntry(value=host, entry_type="domain"))
        return out

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


def extract(text: str) -> list[ExtractedEntry]:
    """Извлечь уникальные индикаторы (домены, IP, URL, хеши) из текста письма."""
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

    # Домены из e-mail (встречаются внутри предложений, напр. отправитель).
    for host in _EMAIL_RE.findall(text):
        host = _normalize_domain(host)
        if is_valid_domain(host) and host not in _ALLOWLIST:
            _add_many([ExtractedEntry(value=host, entry_type="domain")])

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


def _text_from_pdf(data: bytes) -> str:
    from pypdf import PdfReader

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
