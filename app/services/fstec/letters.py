"""Разбор пачки файлов в письма ФСТЭК.

Задача модуля — принять произвольную пачку файлов («загрузить всё скопом») и
самостоятельно разложить её по письмам:

  1. из каждого файла достаётся текст и индикаторы;
  2. из текста (а если там нет — из имени файла) вытаскиваются реквизиты:
     номер письма и дата;
  3. файлы с одинаковым номером считаются одним письмом: само письмо и
     приложения к нему оказываются в одной группе;
  4. файлы без номера прилипают к письму пачки, если оно там одно —
     приложения обычно номера не содержат.

Разбор ничего не сохраняет: он возвращает структуру, которую оператор видит
на предпросмотре и может поправить до записи в базу.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import date

from .lib import doc_parser

# --- Реквизиты письма ------------------------------------------------------

# Номер письма ФСТЭК: 240/24/1234, реже с буквенной частью — 240/24/1234-дсп.
# Требуем не меньше двух разделителей «/», иначе под шаблон попадают даты
# и обычные дроби из текста.
_NUMBER_RE = re.compile(
    r"\b(\d{1,4}\s*/\s*\d{1,3}\s*/\s*\d{1,6}(?:\s*[-–]\s*[а-яё\w]{1,8})?)\b",
    re.IGNORECASE,
)
# «№ 240/24/1234» — приоритетный вариант: рядом стоит знак номера.
_NUMBER_MARKED_RE = re.compile(
    r"(?:№|N[o°]?\s|исх\.?\s*№?)\s*"
    r"(\d{1,4}\s*/\s*\d{1,3}\s*/\s*\d{1,6}(?:\s*[-–]\s*[а-яё\w]{1,8})?)",
    re.IGNORECASE,
)
# Номер в имени файла: 240-24-1234.pdf, 240_24_1234 прил.1.docx
_NUMBER_IN_NAME_RE = re.compile(r"(\d{1,4})[-_/](\d{1,3})[-_/](\d{1,6})")

_DATE_DOTTED_RE = re.compile(r"\b(\d{1,2})\.(\d{1,2})\.(\d{4})\b")
_MONTHS = {
    "января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5,
    "июня": 6, "июля": 7, "августа": 8, "сентября": 9, "октября": 10,
    "ноября": 11, "декабря": 12,
}
_DATE_WORDS_RE = re.compile(
    r"[«\"]?(\d{1,2})[»\"]?\s+(" + "|".join(_MONTHS) + r")\s+(\d{4})",
    re.IGNORECASE,
)
# Дата, стоящая сразу после номера письма («от 15.03.2024») — самая надёжная.
_DATE_AFTER_NUMBER_RE = re.compile(r"\bот\s+", re.IGNORECASE)

# Реквизиты ищем только в начале документа: дальше по тексту встречаются даты
# обнаружения атак и номера чужих писем, которые к самому письму отношения
# не имеют.
HEAD_CHARS = 2000


def normalize_number(value: str) -> str:
    """Ключ для склейки писем: «№ 240/24/1234 » и «240 / 24 / 1234» — одно.

    Пустая строка означает, что номер распознать не удалось.
    """
    if not value:
        return ""
    cleaned = re.sub(r"[^\d/а-яё-]", "", str(value).lower().replace("№", ""))
    cleaned = re.sub(r"/+", "/", cleaned).strip("/-")
    return cleaned


def extract_number(text: str, filename: str = "") -> str:
    """Найти номер письма — сначала в тексте, потом в имени файла."""
    head = (text or "")[:HEAD_CHARS]

    match = _NUMBER_MARKED_RE.search(head)
    if not match:
        match = _NUMBER_RE.search(head)
    if match:
        return re.sub(r"\s*", "", match.group(1))

    stem = os.path.splitext(filename or "")[0]
    match = _NUMBER_IN_NAME_RE.search(stem)
    if match:
        return "/".join(match.groups())
    return ""


def extract_date(text: str) -> date | None:
    """Найти дату письма. Предпочитаем ту, что стоит после «от»."""
    head = (text or "")[:HEAD_CHARS]

    # Сначала — дата сразу после «от»: именно так пишут дату самого письма.
    for marker in _DATE_AFTER_NUMBER_RE.finditer(head):
        tail = head[marker.end():marker.end() + 40]
        parsed = _first_date(tail)
        if parsed:
            return parsed
    return _first_date(head)


def _first_date(chunk: str) -> date | None:
    match = _DATE_DOTTED_RE.search(chunk)
    if match:
        day, month, year = (int(x) for x in match.groups())
        return _safe_date(year, month, day)

    match = _DATE_WORDS_RE.search(chunk)
    if match:
        day = int(match.group(1))
        month = _MONTHS[match.group(2).lower()]
        return _safe_date(int(match.group(3)), month, day)
    return None


def _safe_date(year: int, month: int, day: int) -> date | None:
    try:
        return date(year, month, day)
    except ValueError:      # 31.02 и прочие опечатки в документе
        return None


# --- Разбор пачки ----------------------------------------------------------

@dataclass
class ParsedFile:
    """Один загруженный файл: что в нём нашли и куда он относится."""

    index: int
    filename: str
    data: bytes
    sha256: str
    content_type: str = ""
    number: str = ""
    letter_date: date | None = None
    entries: list = field(default_factory=list)
    # Почему индикаторов нет: нет библиотеки для формата, битый файл и т.п.
    error: str = ""
    # Файл уже загружен раньше — сюда попадает номер того письма.
    duplicate_of: str = ""
    # Основной файл письма (в нём нашлись реквизиты), а не приложение.
    is_primary: bool = False

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class ParsedLetter:
    """Группа файлов, признанных одним письмом."""

    number: str
    letter_date: date | None
    files: list[ParsedFile] = field(default_factory=list)

    @property
    def number_key(self) -> str:
        return normalize_number(self.number)

    @property
    def entries_count(self) -> int:
        return sum(len(f.entries) for f in self.files)


def parse_files(uploaded, known_hashes=None) -> list[ParsedFile]:
    """Разобрать загруженные файлы по одному.

    ``uploaded`` — последовательность пар ``(имя файла, содержимое, mime)``.
    ``known_hashes`` — отображение sha256 → номер письма для уже загруженных
    файлов: повторную загрузку того же документа отмечаем, но не роняем.
    """
    known_hashes = known_hashes or {}
    result: list[ParsedFile] = []

    for index, (filename, data, mimetype) in enumerate(uploaded):
        digest = hashlib.sha256(data).hexdigest()
        parsed = ParsedFile(
            index=index,
            filename=filename,
            data=data,
            sha256=digest,
            content_type=mimetype or "",
            duplicate_of=known_hashes.get(digest, ""),
        )

        text = ""
        try:
            text = doc_parser.extract_text_from_file(filename, data)
        except doc_parser.MissingDependency as exc:
            parsed.error = str(exc)
        except ValueError as exc:
            parsed.error = str(exc)
        except Exception as exc:  # noqa: BLE001 — повреждённый документ
            parsed.error = f"не удалось прочитать файл: {exc}"

        if text:
            try:
                parsed.entries = doc_parser.extract(text)
            except Exception as exc:  # noqa: BLE001
                parsed.error = f"не удалось разобрать текст: {exc}"

        parsed.number = extract_number(text, filename)
        parsed.letter_date = extract_date(text)
        # Реквизиты нашлись в самом тексте — значит это письмо, а не приложение.
        parsed.is_primary = bool(parsed.number and text)
        result.append(parsed)

    return result


def group_into_letters(files: list[ParsedFile], forced_number: str = "",
                       forced_date: date | None = None) -> list[ParsedLetter]:
    """Разложить разобранные файлы по письмам.

    Если оператор явно указал номер, вся пачка — одно письмо: это привычный
    случай «письмо вместе с приложениями», и угадывать тут нечего.
    """
    if not files:
        return []

    if forced_number:
        letter_date = forced_date or next(
            (f.letter_date for f in files if f.letter_date), None
        )
        return [ParsedLetter(number=forced_number, letter_date=letter_date,
                             files=list(files))]

    groups: dict[str, ParsedLetter] = {}
    orphans: list[ParsedFile] = []

    for parsed in files:
        key = normalize_number(parsed.number)
        if not key:
            orphans.append(parsed)
            continue
        letter = groups.get(key)
        if letter is None:
            groups[key] = ParsedLetter(number=parsed.number,
                                       letter_date=parsed.letter_date,
                                       files=[parsed])
        else:
            letter.files.append(parsed)
            # Дата могла найтись не в первом файле группы.
            if letter.letter_date is None:
                letter.letter_date = parsed.letter_date

    letters = list(groups.values())

    if orphans:
        if len(letters) == 1:
            # Приложения к единственному письму пачки: номера в них нет,
            # но принадлежность очевидна.
            letters[0].files.extend(orphans)
        else:
            # Либо писем несколько (гадать нельзя), либо номеров нет вовсе —
            # такие файлы уезжают в письмо «без номера», его оператор
            # поправит на предпросмотре.
            letters.append(ParsedLetter(
                number="", letter_date=forced_date or next(
                    (f.letter_date for f in orphans if f.letter_date), None),
                files=orphans,
            ))

    letters.sort(key=lambda x: min(f.index for f in x.files))
    return letters


def parse_batch(uploaded, known_hashes=None, forced_number: str = "",
                forced_date: date | None = None) -> list[ParsedLetter]:
    """Полный разбор пачки: файлы → реквизиты → группировка по письмам."""
    return group_into_letters(
        parse_files(uploaded, known_hashes), forced_number, forced_date
    )
