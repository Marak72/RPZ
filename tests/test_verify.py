"""Проверка индикаторов, извлечённых из PDF.

Автоматически исправить подмену символа нельзя — угадать исходный невозможно.
Задача проверок скромнее: показать аналитику, на что смотреть.
"""
from app.services.fstec.lib import doc_parser, verify


# --- смешанные алфавиты ----------------------------------------------------

def test_cyrillic_letter_inside_a_latin_domain_is_caught():
    """«о» кириллицей в gооgle.com — классический результат распознавания."""
    notes = verify.warnings_for("g\u043eogle.com")
    assert notes
    assert "алфавит" in notes[0]


def test_fully_latin_domain_is_clean():
    assert verify.warnings_for("evil-domain.ru") == []


def test_fully_cyrillic_name_is_flagged_too():
    """В письме домен приводится латиницей или в punycode, но не кириллицей."""
    notes = verify.warnings_for("сайт.рф")
    assert notes


def test_punycode_domain_is_not_flagged():
    assert verify.warnings_for("xn--80aswg.xn--p1ai") == []


# --- цифры, похожие на буквы -----------------------------------------------

def test_digit_between_letters_is_flagged():
    notes = verify.warnings_for("micr0soft.com")
    assert any("цифры между букв" in n for n in notes)


def test_digit_at_the_edge_is_not_flagged():
    """s3.amazonaws.com и site24.ru — обычные имена, тревожить незачем."""
    assert verify.warnings_for("s3.amazonaws.com") == []
    assert verify.warnings_for("site24.ru") == []


def test_ip_is_never_flagged_for_digits():
    assert verify.warnings_for("192.168.0.1", "ip") == []


# --- хеши ------------------------------------------------------------------

def test_non_hex_character_in_a_hash_is_caught():
    """У хеша алфавит задан жёстко, поэтому подмена видна точно."""
    notes = verify.warnings_for("2f150acc59944edb992fcccc5e40534g", "md5")
    assert notes


def test_correct_hash_is_clean():
    assert verify.warnings_for("2f150acc59944edb992fcccc5e405349", "md5") == []


# --- источник --------------------------------------------------------------

def test_pdf_is_recognised_by_extension():
    assert verify.is_pdf("prilozhenie.PDF")
    assert not verify.is_pdf("pismo.docx")


# --- исходная строка письма ------------------------------------------------

def test_entry_remembers_the_line_it_came_from():
    """Без исходной строки сверять подмену не с чем."""
    text = ("Вредоносные ресурсы:\n"
            "evil-domain[.]ru;\n"
            "прочий текст\n")
    entry = [e for e in doc_parser.extract(text) if e.value == "evil-domain.ru"][0]
    assert entry.context == "evil-domain[.]ru;"


def test_context_keeps_the_masking_as_written():
    """Показываем строку как в письме, с маскировкой, а не после обработки."""
    entry = doc_parser.extract("адрес hxxp[:]//evil[.]ru/a;")[0]
    assert "hxxp" in entry.context


# --- строки, не прошедшие проверку -----------------------------------------

def test_homoglyph_domain_is_reported_instead_of_being_dropped():
    """Раньше такая строка пропадала молча — а это и есть подмена символа."""
    text = "Вредоносные ресурсы:\ng\u043eogle-drive[.]net;\n"
    # Разбор её не берёт: кириллическая «о» не проходит проверку имени.
    assert doc_parser.extract(text) == []
    # Но и потерять её нельзя.
    found = dict(doc_parser.unparsed_candidates(text))
    assert "g\u043eogle-drive.net" in found
    assert "не латиницей" in found["g\u043eogle-drive.net"]


def test_hash_with_a_wrong_letter_is_reported():
    text = "2f150acc59944edb992fcccc5e40534g;\n"
    found = dict(doc_parser.unparsed_candidates(text))
    assert "2f150acc59944edb992fcccc5e40534g" in found
    assert "хеш" in found["2f150acc59944edb992fcccc5e40534g"]


def test_valid_indicators_are_not_reported_as_unparsed():
    text = "evil-domain[.]ru;\n1.2.3.4;\n"
    assert doc_parser.unparsed_candidates(text) == []


def test_ordinary_sentences_are_not_reported():
    """Иначе список «не распознано» завалило бы обычным текстом письма."""
    text = ("В ходе мониторинга выявлены компьютерные атаки.\n"
            "Просим принять меры по блокированию.\n")
    assert doc_parser.unparsed_candidates(text) == []


def test_attachment_names_are_not_reported():
    text = "Во вложении файл otchet.docx с описанием.\n"
    assert doc_parser.unparsed_candidates(text) == []
