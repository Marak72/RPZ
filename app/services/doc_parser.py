"""Извлечение доменов и IP-адресов из писем ФСТЭК (.docx / .odt).

Учитывает распространённые приёмы маскировки индикаторов (defang):
example[.]com, hxxp://, и т.п. — приводит их к нормальному виду перед извлечением.

Функции извлечения работают со строкой текста, поэтому их легко тестировать
без реальных файлов.
"""
import io
import re
from dataclasses import dataclass

# --- Регулярные выражения -------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


@dataclass
class ExtractedEntry:
    value: str
    entry_type: str  # domain / ip


# --- Нормализация (refang) ------------------------------------------------

def refang(text: str) -> str:
    """Убрать типовую маскировку индикаторов."""
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = text.replace("[:]", ":").replace("(:)", ":")
    text = re.sub(r"\bhxxps\b", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhxxp\b", "http", text, flags=re.IGNORECASE)
    # "example [.] com" -> "example.com"
    text = re.sub(r"\s*\[\.\]\s*", ".", text)
    text = re.sub(r"\s+\.\s+", ".", text)
    return text


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract(text: str) -> list[ExtractedEntry]:
    """Извлечь уникальные домены и IP из произвольного текста."""
    text = refang(text)
    seen: set[str] = set()
    result: list[ExtractedEntry] = []

    # Сначала IP, чтобы не спутать их с доменами.
    for match in _IPV4_RE.findall(text):
        if _valid_ipv4(match) and match not in seen:
            seen.add(match)
            result.append(ExtractedEntry(value=match, entry_type="ip"))

    for match in _DOMAIN_RE.findall(text):
        value = match.lower().rstrip(".")
        if value in seen:
            continue
        # пропустить то, что на самом деле является IP
        if _valid_ipv4(value):
            continue
        seen.add(value)
        result.append(ExtractedEntry(value=value, entry_type="domain"))

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
