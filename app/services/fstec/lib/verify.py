"""Проверка индикаторов, извлечённых из ненадёжного источника (PDF).

Зачем. Из .docx и .odt текст берётся ровно тот, что набрал автор письма. Из
PDF — нет: там нет «текста» как такового, есть глифы со своими кодировками,
и восстановление строки зависит от того, как документ собран. Отсюда типовые
подмены: латинская ``O`` превращается в цифру ``0``, ``l`` в ``1``, а если
письмо ещё и распознавали — то и в кириллическую ``О``. Индикатор при этом
выглядит правдоподобно, но ведёт не туда: заблокируем не тот домен, а
настоящий останется работать.

Автоматически «исправлять» такое нельзя — угадать исходный символ
невозможно. Поэтому задача модуля скромнее и честнее: **показать аналитику,
на что смотреть**. Он отмечает признаки подмены и ничего не решает сам.
"""
from __future__ import annotations

import re
import unicodedata

#: Символы, которые в шрифтах выглядят почти одинаково. Ключ — то, что
#: получилось, значение — то, чем оно могло быть на самом деле.
CONFUSABLE = {
    "0": "O/o",
    "1": "l/I",
    "5": "S",
    "8": "B",
    "6": "b",
    "9": "g",
    "2": "Z",
}

#: Латиница, цифры и знаки, допустимые в имени домена.
_ASCII_DOMAIN = re.compile(r"^[a-z0-9.\-_@]+$")
#: Буква (любого алфавита) — чтобы отличить букву от цифры и знака.
_LETTER = re.compile(r"[^\W\d_]", re.UNICODE)


def _scripts(value: str) -> set[str]:
    """Какими алфавитами написана строка."""
    found = set()
    for char in value:
        if not _LETTER.match(char):
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            found.add("неизвестный")
            continue
        if name.startswith("CYRILLIC"):
            found.add("кириллица")
        elif name.startswith("LATIN"):
            found.add("латиница")
        elif name.startswith("GREEK"):
            found.add("греческий")
        else:
            found.add("иной")
    return found


def mixed_scripts(value: str) -> set[str]:
    """Алфавиты, если их больше одного. Пустое множество — всё в порядке."""
    scripts = _scripts(value)
    return scripts if len(scripts) > 1 else set()


def confusable_digits(value: str) -> list[str]:
    """Цифры внутри буквенной части — там, где ожидалась бы буква.

    Цифра в домене сама по себе законна (``s3.amazonaws.com``), поэтому
    отмечаем только зажатую между буквами: ``micr0soft`` подозрителен,
    ``site24`` нет.
    """
    out = []
    for label in value.split("@")[-1].split("."):
        # Punycode кодирует нелатинские имена, и цифры между букв там — норма:
        # xn--p1ai это «.рф». Отмечать такие метки значит ругаться на каждый
        # русскоязычный домен.
        if label.startswith("xn--"):
            continue
        for index, char in enumerate(label):
            if char not in CONFUSABLE:
                continue
            left = label[index - 1] if index else ""
            right = label[index + 1] if index + 1 < len(label) else ""
            if _LETTER.match(left or "") and _LETTER.match(right or ""):
                out.append("%s (похоже на %s)" % (char, CONFUSABLE[char]))
    return out


def warnings_for(value: str, entry_type: str = "domain") -> list[str]:
    """На что аналитику стоит посмотреть глазами.

    Пустой список означает «явных признаков подмены нет». Это не гарантия
    правильности — только отсутствие того, что можно проверить машинально.
    """
    if not value:
        return []

    notes: list[str] = []

    # Хеш проверяется точно: длина и алфавит заданы жёстко, поэтому любая
    # подмена символа видна сразу.
    if entry_type in ("sha256", "sha1", "md5"):
        if not re.fullmatch(r"[0-9a-f]+", value, re.IGNORECASE):
            notes.append("в хеше есть символы, которых в нём быть не может")
        return notes

    if entry_type == "ip":
        return notes

    scripts = mixed_scripts(value)
    if scripts:
        # Самый надёжный признак: настоящее доменное имя пишется латиницей,
        # а кириллический домен в письме приводится в punycode (xn--…).
        notes.append(
            "смешаны алфавиты (%s) — вероятна подмена похожей буквы"
            % ", ".join(sorted(scripts))
        )
    elif "кириллица" in _scripts(value):
        notes.append(
            "имя написано кириллицей — в письме домен должен быть латиницей "
            "или в виде xn--…"
        )

    digits = confusable_digits(value.lower())
    if digits:
        notes.append("цифры между букв: %s" % ", ".join(digits))

    return notes


def is_pdf(filename: str) -> bool:
    return (filename or "").lower().endswith(".pdf")
