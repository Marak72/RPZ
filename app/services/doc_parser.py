"""Извлечение индикаторов компрометации из писем ФСТЭК (.docx / .odt).

В письмах ФСТЭК индикаторы для блокировки приводятся каждый на отдельной строке
(заканчивается «;» или «.»), часто в замаскированном виде (defang):
example[.]com, hxxp[:]//..., 5[.]252[.]153[.]67. Имена вложений, названия ПО и
ссылки-источники сидят внутри обычных предложений — их брать не нужно.

Поэтому индикаторы извлекаются только из сегментов, которые ЦЕЛИКОМ являются
доменом / IP / URL / хешем (для URL берётся только host). Дополнительно из любого
места текста вытягивается домен из e-mail отправителя.

Функции работают со строкой текста, поэтому их легко тестировать без файлов.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass
from urllib.parse import urlparse

# --- Регулярные выражения -------------------------------------------------

_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE
)
_EMAIL_RE = re.compile(
    r"[a-z0-9._%+-]+@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})",
    re.IGNORECASE,
)
# Одиночный индикатор внутри предложения после слова «адрес» (адресу/адреса/…),
# напр.: «к IP-адресу 31[.]56[.]209[.]126,» или «к адресу crystalxrat[.]net,».
_INLINE_ADDR_RE = re.compile(r"адрес[ауе]?\s+(\S+)", re.IGNORECASE)
# Хеши: проверяем от длинного к короткому (64 → 40 → 32).
_HASH_TYPES = (("sha256", 64), ("sha1", 40), ("md5", 32))
_HEX_RE = re.compile(r"[0-9a-f]+", re.IGNORECASE)

# Легитимные домены, которые встречаются в тексте писем как ссылки-источники
# и не являются индикаторами для блокировки.
_ALLOWLIST = {"fstec.ru"}


@dataclass
class ExtractedEntry:
    value: str
    entry_type: str  # domain / ip / sha256 / sha1 / md5


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


def _clean_segment(seg: str) -> str:
    """Снять пробелы, обрамляющие кавычки/скобки и хвостовую пунктуацию."""
    seg = seg.strip().strip("«»\"'()[]<>")
    seg = seg.strip().rstrip(".,;:")
    return seg.strip()


def _host_from_url(seg: str) -> str | None:
    try:
        host = urlparse(seg).hostname
    except ValueError:
        return None
    if host and _DOMAIN_RE.fullmatch(host):
        return host.lower()
    return None


def _classify_segment(seg: str) -> ExtractedEntry | None:
    """Классифицировать сегмент, если он ЦЕЛИКОМ является индикатором."""
    if not seg:
        return None

    # URL — берём только host.
    if "://" in seg or seg.lower().startswith(("http", "ftp")) and "/" in seg:
        host = _host_from_url(seg)
        if host and host not in _ALLOWLIST:
            return ExtractedEntry(value=host, entry_type="domain")
        return None

    # IPv4 целиком.
    if _IPV4_RE.fullmatch(seg):
        return ExtractedEntry(value=seg, entry_type="ip") if _valid_ipv4(seg) else None

    # Хеш целиком (hex фиксированной длины).
    if _HEX_RE.fullmatch(seg):
        for htype, length in _HASH_TYPES:
            if len(seg) == length:
                return ExtractedEntry(value=seg.lower(), entry_type=htype)
        return None

    # Домен целиком.
    if _DOMAIN_RE.fullmatch(seg):
        value = seg.lower().lstrip(".")
        if value.startswith("www."):
            value = value[4:]
        if value not in _ALLOWLIST:
            return ExtractedEntry(value=value, entry_type="domain")

    return None


def extract(text: str) -> list[ExtractedEntry]:
    """Извлечь уникальные индикаторы (домены, IP, хеши) из текста письма."""
    text = refang(text)
    seen: set[str] = set()
    result: list[ExtractedEntry] = []

    def _add(entry: ExtractedEntry | None) -> None:
        if entry and entry.value not in seen:
            seen.add(entry.value)
            result.append(entry)

    # Индикаторы из «строк-индикаторов»: строка → сегменты по ';' → классификация.
    for line in text.splitlines():
        for raw_seg in line.split(";"):
            _add(_classify_segment(_clean_segment(raw_seg)))

    # Одиночные индикаторы внутри предложений после слова «адрес».
    for m in _INLINE_ADDR_RE.finditer(text):
        _add(_classify_segment(_clean_segment(m.group(1))))

    # Домены из e-mail (встречаются внутри предложений, напр. отправитель).
    for host in _EMAIL_RE.findall(text):
        host = host.lower()
        if host not in _ALLOWLIST:
            _add(ExtractedEntry(value=host, entry_type="domain"))

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


def extract_from_file(filename: str, data: bytes) -> list[ExtractedEntry]:
    """Извлечь индикаторы из загруженного файла по его расширению."""
    lower = filename.lower()
    if lower.endswith(".docx"):
        text = _text_from_docx(data)
    elif lower.endswith(".odt"):
        text = _text_from_odt(data)
    else:
        raise ValueError("Поддерживаются только файлы .docx и .odt")
    return extract(text)
