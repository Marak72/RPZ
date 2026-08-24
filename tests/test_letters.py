"""Письма ФСТЭК: массовая загрузка, группировка файлов по письмам, экспорт.

Главное, что здесь проверяется: письмо — это НОМЕР, а не файл. Файлы одного
письма попадают в одну карточку, а индикатор помнит все письма, в которых
встретился.
"""
import io

import pytest
from cryptography.fernet import Fernet

from config import Config

from app import create_app
from app.core.extensions import db
from app.core.models import User, UserService
from app.portal import SERVICES
from app.services.fstec import letters as letters_lib
from app.services.fstec import routes as main_routes
from app.services.fstec.models import (
    STATUS_FALSE_POSITIVE,
    STATUS_IGNORED,
    STATUS_NEW,
    BlockEntry,
    IocHash,
    Letter,
    LetterFile,
    UrlEntry,
)

# Минимальные письма: индикаторы на отдельных строках — так их видит парсер.
LETTER_A = """ФСТЭК России
исх. № 240/24/1001 от 15.03.2026

evil-alpha.ru
203.0.113.10
"""

LETTER_B = """ФСТЭК России
исх. № 240/24/2002 от 16.03.2026

evil-beta.ru
198.51.100.7
"""

# Приложение к письму 240/24/1001: номера в тексте нет.
APPENDIX_A = """Приложение к письму

evil-appendix.ru
"""

# Второе письмо с тем же доменом, что и в LETTER_A.
LETTER_C = """ФСТЭК России
исх. № 240/24/3003 от 20.03.2026

evil-alpha.ru
"""


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    RPZ_FERNET_KEY = Fernet.generate_key().decode()


@pytest.fixture
def app(tmp_path, monkeypatch):
    # Разбор .docx/.odt требует необязательных библиотек, которых может не быть.
    # Здесь проверяется работа с письмами, а не разбор форматов, поэтому текст
    # берётся из файла напрямую.
    monkeypatch.setattr(
        letters_lib.doc_parser, "extract_text_from_file",
        lambda filename, data: data.decode("utf-8"),
    )
    application = create_app(TestConfig)
    application.config["LETTERS_DIR"] = str(tmp_path / "letters")
    with application.app_context():
        db.create_all()
        user = User(username="op", role="operator")
        user.set_password("pass")
        db.session.add(user)
        db.session.flush()
        # Доступ к сервисам выдаёт администратор — без выдачи будет 403.
        for service in SERVICES:
            db.session.add(UserService(user_id=user.id, service_id=service.id))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    test_client = app.test_client()
    test_client.post("/login", data={"username": "op", "password": "pass"})
    return test_client


def _upload(client, files, **extra):
    """Загрузить письма и вернуть страницу предпросмотра."""
    data = {
        "documents": [(io.BytesIO(body), name) for name, body in files],
        "submit": "1",
    }
    data.update(extra)
    return client.post("/fstec/upload", data=data,
                       content_type="multipart/form-data")


def _groups_json(page: str) -> str:
    """Достать скрытое поле groups_json со страницы предпросмотра."""
    marker = 'name="groups_json" value="'
    start = page.index(marker) + len(marker)
    end = page.index('"', start)
    return (page[start:end].replace("&#34;", '"').replace("&amp;", "&")
            .replace("&lt;", "<").replace("&gt;", ">").replace("&#39;", "'"))


def _save(client, values, groups_json, **extra):
    data = {"selected": values, "groups_json": groups_json}
    data.update(extra)
    return client.post("/fstec/preview", data=data, follow_redirects=True)


def _upload_and_save(client, files, selected, **extra):
    page = _upload(client, files, **extra).get_data(as_text=True)
    return _save(client, selected, _groups_json(page), **extra)


# --- Разбор реквизитов (без базы) ------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("исх. № 240/24/1001 от 15.03.2026", "240/24/1001"),
    ("№ 240/24/1234", "240/24/1234"),
    ("Письмо 240/54/9876 о компьютерных атаках", "240/54/9876"),
    ("никакого номера тут нет", ""),
])
def test_number_is_extracted_from_text(text, expected):
    assert letters_lib.extract_number(text) == expected


def test_number_falls_back_to_filename():
    """У приложений номер часто есть только в имени файла."""
    assert letters_lib.extract_number("", "240-24-1001 прил.1.pdf") == "240/24/1001"


def test_number_key_glues_the_same_number_written_differently():
    variants = ["240/24/1001", "№ 240/24/1001 ", "240 / 24 / 1001"]
    keys = {letters_lib.normalize_number(v) for v in variants}
    assert len(keys) == 1


@pytest.mark.parametrize("text, iso", [
    ("исх. № 240/24/1001 от 15.03.2026", "2026-03-15"),
    ("от «5» марта 2026 г.", "2026-03-05"),
    ("от 31.02.2026", None),          # опечатка в документе — не падаем
])
def test_date_is_extracted(text, iso):
    found = letters_lib.extract_date(text)
    assert (found.isoformat() if found else None) == iso


def test_dates_deeper_in_the_text_are_ignored():
    """Дальше по тексту идут даты атак — датой письма они не являются."""
    text = ("исх. № 240/24/1001 от 15.03.2026\n"
            + "прочее\n" * 300 + "01.01.2020\n")
    assert letters_lib.extract_date(text).isoformat() == "2026-03-15"


# --- Группировка файлов в письма -------------------------------------------

def test_files_with_the_same_number_form_one_letter(client):
    page = _upload(client, [
        ("pismo.odt", LETTER_A.encode()),
        ("kopiya.odt", LETTER_A.encode().replace(b"evil-alpha", b"evil-copy")),
    ]).get_data(as_text=True)
    assert page.count('name="group_number_') == 1


def test_appendix_without_number_joins_the_only_letter(client):
    _upload_and_save(
        client,
        [("pismo.odt", LETTER_A.encode()),
         ("prilozhenie.odt", APPENDIX_A.encode())],
        ["0|evil-alpha.ru", "1|evil-appendix.ru"],
    )
    letter = Letter.query.one()
    assert letter.number == "240/24/1001"
    assert len(letter.files) == 2
    # Индикатор из приложения принадлежит тому же письму.
    values = {e.value for e in letter.block_entries}
    assert {"evil-alpha.ru", "evil-appendix.ru"} <= values


def test_two_different_letters_stay_separate(client):
    _upload_and_save(
        client,
        [("a.odt", LETTER_A.encode()), ("b.odt", LETTER_B.encode())],
        ["0|evil-alpha.ru", "1|evil-beta.ru"],
    )
    numbers = {letter.number for letter in Letter.query.all()}
    assert numbers == {"240/24/1001", "240/24/2002"}


def test_explicit_number_forces_a_single_letter(client):
    """Оператор указал номер — вся пачка относится к нему, гадать нельзя."""
    _upload_and_save(
        client,
        [("a.odt", LETTER_A.encode()), ("b.odt", LETTER_B.encode())],
        ["0|evil-alpha.ru", "1|evil-beta.ru"],
        letter_number="240/24/9999",
    )
    letter = Letter.query.one()
    assert letter.number == "240/24/9999"
    assert len(letter.files) == 2


def test_orphan_group_merges_when_given_an_existing_number(client):
    """В пачке два письма и приложение — принадлежность приложения неочевидна.

    Разбор честно выделяет его в группу «без номера», а оператор одним полем
    на предпросмотре отправляет её в нужное письмо.
    """
    page = _upload(client, [
        ("pismo1.odt", LETTER_A.encode()),
        ("prilozhenie.odt", APPENDIX_A.encode()),
        ("pismo2.odt", LETTER_B.encode()),
    ]).get_data(as_text=True)
    # Три группы: два письма и «без номера».
    assert page.count('name="group_number_') == 3

    _save(client, ["0|evil-alpha.ru", "1|evil-appendix.ru", "2|evil-beta.ru"],
          _groups_json(page),
          group_number_0="240/24/1001", group_number_1="240/24/1001",
          group_number_2="240/24/2002")

    assert Letter.query.count() == 2
    first = Letter.query.filter_by(number="240/24/1001").one()
    assert len(first.files) == 2
    assert {e.value for e in first.block_entries} >= {
        "evil-alpha.ru", "evil-appendix.ru"
    }


def test_letter_date_is_recognised(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    assert Letter.query.one().letter_date.isoformat() == "2026-03-15"


# --- Дозагрузка и дедупликация ---------------------------------------------

def test_second_upload_joins_the_existing_letter(client):
    """Приложение пришло позже — двойника письма заводить нельзя."""
    _upload_and_save(client, [("pismo.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    _upload_and_save(client, [("prilozhenie.odt", APPENDIX_A.encode())],
                     ["0|evil-appendix.ru"], letter_number="240/24/1001")

    letter = Letter.query.one()
    assert len(letter.files) == 2
    assert {e.value for e in letter.block_entries} == {
        "evil-alpha.ru", "evil-appendix.ru"
    }


def test_same_file_uploaded_twice_is_not_stored_again(client):
    _upload_and_save(client, [("pismo.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])

    # О повторе предупреждаем сразу на предпросмотре — до сохранения.
    page = _upload(client, [("pismo.odt", LETTER_A.encode())]).get_data(as_text=True)
    assert "уже загружен" in page

    _save(client, ["0|evil-alpha.ru"], _groups_json(page))
    assert LetterFile.query.count() == 1
    assert Letter.query.count() == 1


def test_files_are_hashed_on_save(client):
    _upload_and_save(client, [("pismo.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    assert len(LetterFile.query.one().sha256) == 64


# --- Связь индикатор ↔ письмо ----------------------------------------------

def test_indicator_from_two_letters_keeps_both_sources(client):
    """Раньше повторный индикатор молча терял связь со вторым письмом."""
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    _upload_and_save(client, [("c.odt", LETTER_C.encode())],
                     ["0|evil-alpha.ru"])

    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    assert {letter.number for letter in entry.letters} == {
        "240/24/1001", "240/24/3003"
    }
    # Сам индикатор при этом остаётся единственной записью.
    assert BlockEntry.query.filter_by(value="evil-alpha.ru").count() == 1


def test_letter_page_shows_files_and_indicators(client):
    _upload_and_save(
        client,
        [("pismo.odt", LETTER_A.encode()),
         ("prilozhenie.odt", APPENDIX_A.encode())],
        ["0|evil-alpha.ru", "0|203.0.113.10", "1|evil-appendix.ru"],
    )
    letter = Letter.query.one()
    body = client.get(f"/fstec/letters/{letter.id}").get_data(as_text=True)

    assert "240/24/1001" in body
    assert "pismo.odt" in body and "prilozhenie.odt" in body
    assert "evil-alpha.ru" in body and "evil-appendix.ru" in body


def test_deleting_a_letter_keeps_the_indicators(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    letter = Letter.query.one()
    client.post(f"/fstec/letters/{letter.id}/delete", follow_redirects=True)

    assert Letter.query.count() == 0
    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    assert entry.letters == []


# --- Правка реквизитов ------------------------------------------------------

def test_letter_number_can_be_fixed_afterwards(client):
    _upload_and_save(client, [("x.odt", APPENDIX_A.encode())],
                     ["0|evil-appendix.ru"])
    letter = Letter.query.one()
    assert letter.number == ""

    client.post(f"/fstec/letters/{letter.id}/edit",
                data={"number": "240/24/5005", "letter_date": "2026-04-01"},
                follow_redirects=True)
    letter = Letter.query.one()
    assert letter.number == "240/24/5005"
    assert letter.number_key == "240/24/5005"


def test_duplicate_letter_number_is_rejected(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    _upload_and_save(client, [("b.odt", LETTER_B.encode())],
                     ["0|evil-beta.ru"])
    second = Letter.query.filter_by(number="240/24/2002").one()

    response = client.post(f"/fstec/letters/{second.id}/edit",
                           data={"number": "240/24/1001"},
                           follow_redirects=True)
    assert "уже есть в архиве" in response.get_data(as_text=True)
    assert Letter.query.filter_by(number="240/24/2002").count() == 1


# --- Массовые действия ------------------------------------------------------

def test_bulk_marks_false_positive_with_a_reason(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru", "0|203.0.113.10"])
    ids = [str(e.id) for e in BlockEntry.query.all()]

    client.post("/fstec/candidates/bulk",
                data={"action": "fp", "ids": ids, "note": "в письме опечатка"},
                follow_redirects=True)

    for entry in BlockEntry.query.all():
        assert entry.status == STATUS_FALSE_POSITIVE
        assert entry.decision_note == "в письме опечатка"


def test_bulk_decision_requires_a_reason(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()

    response = client.post("/fstec/candidates/bulk",
                           data={"action": "ignore", "ids": [str(entry.id)]},
                           follow_redirects=True)
    assert "Укажите причину" in response.get_data(as_text=True)
    assert BlockEntry.query.filter_by(value="evil-alpha.ru").one().status \
        == STATUS_NEW


def test_dismissed_domain_is_not_pushable(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    assert entry.is_pushable

    client.post("/fstec/candidates/bulk",
                data={"action": "ignore", "ids": [str(entry.id)],
                      "note": "легитимный сервис"},
                follow_redirects=True)
    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    assert entry.status == STATUS_IGNORED
    assert not entry.is_pushable


def test_bulk_restore_returns_the_entry_to_work(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    client.post("/fstec/candidates/bulk",
                data={"action": "fp", "ids": [str(entry.id)], "note": "ошибка"},
                follow_redirects=True)
    client.post("/fstec/candidates/bulk",
                data={"action": "restore", "ids": [str(entry.id)]},
                follow_redirects=True)

    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    assert entry.status == STATUS_NEW
    assert entry.decision_note == ""


def test_bulk_delete_removes_entries(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    client.post("/fstec/candidates/bulk",
                data={"action": "delete", "ids": [str(entry.id)]},
                follow_redirects=True)
    assert BlockEntry.query.filter_by(value="evil-alpha.ru").count() == 0
    # Письмо при этом остаётся.
    assert Letter.query.count() == 1


def test_manager_cannot_run_bulk_actions(app):
    with app.app_context():
        manager = User(username="boss", role="manager")
        manager.set_password("pass")
        db.session.add(manager)
        db.session.flush()
        for service in SERVICES:
            db.session.add(UserService(user_id=manager.id,
                                       service_id=service.id))
        db.session.commit()

    viewer = app.test_client()
    viewer.post("/login", data={"username": "boss", "password": "pass"})
    response = viewer.post("/fstec/candidates/bulk",
                           data={"action": "delete", "ids": ["1"]})
    assert response.status_code == 403


# --- Фильтры и поиск --------------------------------------------------------

def test_candidates_can_be_filtered_by_letter(client):
    _upload_and_save(
        client,
        [("a.odt", LETTER_A.encode()), ("b.odt", LETTER_B.encode())],
        ["0|evil-alpha.ru", "1|evil-beta.ru"],
    )
    first = Letter.query.filter_by(number="240/24/1001").one()
    body = client.get(f"/fstec/candidates?letter={first.id}").get_data(as_text=True)

    assert "evil-alpha.ru" in body
    assert "evil-beta.ru" not in body


def test_candidates_can_be_filtered_by_status(client):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru", "0|203.0.113.10"])
    entry = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    client.post("/fstec/candidates/bulk",
                data={"action": "ignore", "ids": [str(entry.id)],
                      "note": "легитимный"},
                follow_redirects=True)

    body = client.get("/fstec/candidates?status=ignored").get_data(as_text=True)
    assert "evil-alpha.ru" in body
    assert "203.0.113.10" not in body


def test_global_search_finds_across_all_kinds(client, app):
    _upload_and_save(client, [("a.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru"])
    letter = Letter.query.one()
    url = UrlEntry(value="http://evil-alpha.ru/x.php", host="evil-alpha.ru")
    url.letters.append(letter)
    db.session.add(url)
    db.session.commit()

    body = client.get("/fstec/search?q=evil-alpha").get_data(as_text=True)
    assert "evil-alpha.ru" in body
    assert "http://evil-alpha.ru/x.php" in body


def test_global_search_reports_nothing_found(client):
    body = client.get("/fstec/search?q=nosuchdomain").get_data(as_text=True)
    assert "Ничего не найдено" in body


# --- Выгрузка CSV -----------------------------------------------------------

def _letter_with_indicators(client):
    _upload_and_save(client, [("pismo.odt", LETTER_A.encode())],
                     ["0|evil-alpha.ru", "0|203.0.113.10"])
    return Letter.query.one()


def test_letter_csv_contains_its_indicators(client):
    letter = _letter_with_indicators(client)
    response = client.get(f"/fstec/letters/{letter.id}.csv")
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    assert "evil-alpha.ru" in body
    assert "203.0.113.10" in body
    # Реквизиты письма едут вместе с индикаторами.
    assert "240/24/1001" in body
    assert "15.03.2026" in body


def test_letter_csv_is_a_download_with_bom(client):
    letter = _letter_with_indicators(client)
    response = client.get(f"/fstec/letters/{letter.id}.csv")
    assert "attachment" in response.headers["Content-Disposition"]
    # BOM — иначе Excel в русской локали ломает кодировку.
    assert response.get_data().startswith("﻿".encode())


def test_letter_csv_covers_urls_and_hashes(client, app):
    letter = _letter_with_indicators(client)
    url = UrlEntry(value="http://evil-alpha.ru/x.php", host="evil-alpha.ru")
    url.letters.append(letter)
    ioc = IocHash(value="a" * 64, hash_type="sha256")
    ioc.letters.append(letter)
    db.session.add_all([url, ioc])
    db.session.commit()

    body = client.get(f"/fstec/letters/{letter.id}.csv").get_data(as_text=True)
    assert "http://evil-alpha.ru/x.php" in body
    assert "a" * 64 in body
    assert "sha256" in body


def test_all_letters_csv_lists_every_letter(client):
    _upload_and_save(
        client,
        [("a.odt", LETTER_A.encode()), ("b.odt", LETTER_B.encode())],
        ["0|evil-alpha.ru", "1|evil-beta.ru"],
    )
    body = client.get("/fstec/letters.csv").get_data(as_text=True)
    assert "evil-alpha.ru" in body
    assert "evil-beta.ru" in body
    assert "240/24/1001" in body
    assert "240/24/2002" in body


def test_letter_csv_404_for_unknown_letter(client):
    assert client.get("/fstec/letters/9999.csv").status_code == 404


# --- Прочее -----------------------------------------------------------------

def test_upload_without_files_is_rejected(client):
    response = client.post("/fstec/upload", data={"submit": "1"},
                           content_type="multipart/form-data")
    assert response.status_code == 200
    assert "Выберите хотя бы один файл" in response.get_data(as_text=True)
    assert Letter.query.count() == 0


def test_save_without_groups_json_does_not_create_letters(client):
    response = client.post("/fstec/preview", data={"selected": ["0|evil.ru"]},
                           follow_redirects=True)
    assert response.status_code == 200
    assert Letter.query.count() == 0
    assert BlockEntry.query.count() == 0


def test_duplicate_indicator_across_files_shown_once(client):
    page = _upload(client, [
        ("a.odt", LETTER_A.encode()),
        ("b.odt", LETTER_A.encode().replace(b"1001", b"2002")),
    ]).get_data(as_text=True)
    assert page.count('value="0|evil-alpha.ru"') == 1
    assert 'value="1|evil-alpha.ru"' not in page


def test_push_view_links_source_to_its_letter(client):
    letter = _letter_with_indicators(client)
    body = client.get("/fstec/push").get_data(as_text=True)
    # Источник — ссылка на письмо, а не просто имя файла.
    assert f"/fstec/letters/{letter.id}" in body
    assert "240/24/1001" in body


# --- Адреса электронной почты ----------------------------------------------

LETTER_WITH_EMAIL = (
    "Исх. № 240/24/5000 от 20.08.2026\n"
    "Рассылка велась с адресов:\n"
    "zloumyshlennik@mail.ru;\n"
    "admin@roskomnadsor.ru;\n"
    "Вредоносные домены:\n"
    "evil-domain.ru;\n"
).encode("utf-8")


def _preview_of(client, body=LETTER_WITH_EMAIL, name="pismo.odt"):
    return _upload(client, [(name, body)]).get_data(as_text=True)


def test_mail_service_does_not_reach_the_blocking_tab(client):
    """mail.ru в кандидатах на блокировку означал бы отдел без почты."""
    from app.services.fstec.models import BlockEntry

    page = _preview_of(client)
    _save(client, ["0|evil-domain.ru"], _groups_json(page),
          selected_email=["0|zloumyshlennik@mail.ru",
                          "0|admin@roskomnadsor.ru"])

    domains = {b.value for b in BlockEntry.query.filter_by(entry_type="domain")}
    assert "evil-domain.ru" in domains
    assert "mail.ru" not in domains
    assert "roskomnadsor.ru" not in domains


def test_emails_are_saved_with_their_domain(client):
    from app.services.fstec.models import EmailEntry

    page = _preview_of(client)
    _save(client, [], _groups_json(page),
          selected_email=["0|zloumyshlennik@mail.ru"])

    entry = EmailEntry.query.filter_by(value="zloumyshlennik@mail.ru").first()
    assert entry is not None
    assert entry.host == "mail.ru"
    # Адрес помнит письмо, из которого приехал.
    assert entry.letters


def test_preview_shows_emails_in_their_own_tab(client):
    page = _preview_of(client)
    assert "Адреса почты" in page
    assert "zloumyshlennik@mail.ru" in page


def test_emails_page_lists_them(client):
    page = _preview_of(client)
    _save(client, [], _groups_json(page),
          selected_email=["0|admin@roskomnadsor.ru"])

    body = client.get("/fstec/emails").get_data(as_text=True)
    assert "admin@roskomnadsor.ru" in body
    assert "roskomnadsor.ru" in body


def test_lookalike_domain_can_be_blocked_in_one_click(client):
    """Подделка вроде roskomnadsor.ru живёт только в адресе — её надо блокировать."""
    from app.services.fstec.models import BlockEntry, EmailEntry

    page = _preview_of(client)
    _save(client, [], _groups_json(page),
          selected_email=["0|admin@roskomnadsor.ru"])

    entry = EmailEntry.query.filter_by(value="admin@roskomnadsor.ru").first()
    response = client.post(f"/fstec/emails/{entry.id}/block-host",
                           follow_redirects=True)
    assert response.status_code == 200

    block = BlockEntry.query.filter_by(value="roskomnadsor.ru").first()
    assert block is not None
    assert block.entry_type == "domain"
    assert block.source == "email"
    # Связь с письмом сохранена: иначе в карточке домена не видно, откуда он.
    assert block.letters


def test_blocking_the_same_host_twice_does_not_duplicate(client):
    from app.services.fstec.models import BlockEntry, EmailEntry

    page = _preview_of(client)
    _save(client, [], _groups_json(page),
          selected_email=["0|admin@roskomnadsor.ru"])
    entry = EmailEntry.query.filter_by(value="admin@roskomnadsor.ru").first()

    client.post(f"/fstec/emails/{entry.id}/block-host", follow_redirects=True)
    client.post(f"/fstec/emails/{entry.id}/block-host", follow_redirects=True)

    assert BlockEntry.query.filter_by(value="roskomnadsor.ru").count() == 1


def test_letter_page_shows_its_emails(client):
    from app.services.fstec.models import Letter

    page = _preview_of(client)
    _save(client, [], _groups_json(page),
          selected_email=["0|zloumyshlennik@mail.ru"])

    letter = Letter.query.first()
    body = client.get(f"/fstec/letters/{letter.id}").get_data(as_text=True)
    assert "zloumyshlennik@mail.ru" in body


# --- Индикаторы из PDF -----------------------------------------------------

PDF_LETTER = (
    "Исх. № 240/24/6000 от 21.08.2026\n"
    "Вредоносные ресурсы:\n"
    "micr0soft-update.com;\n"
    "chistiy-domen.ru;\n"
).encode("utf-8")


def _checkbox(page: str, value: str) -> str:
    """Тег чекбокса для конкретного значения — чтобы не гадать по окрестностям."""
    marker = 'value="0|%s"' % value
    end = page.index(marker) + len(marker)
    start = page.rindex("<input", 0, end)
    return page[start:page.index(">", end) + 1]


def test_pdf_indicators_go_to_their_own_tab(client):
    """Из PDF значения выносятся отдельно: там возможна подмена символа."""
    page = _upload(client, [("prilozhenie.pdf", PDF_LETTER)]).get_data(as_text=True)
    assert "Из PDF — проверить" in page
    # Во вкладке доменов их при этом нет — иначе отметились бы дважды.
    domains_tab = page.split("Домены <span", 1)[1].split("</span>", 1)[0]
    assert domains_tab.endswith(">0"), domains_tab


def test_docx_indicators_stay_in_the_usual_tabs(client):
    page = _upload(client, [("pismo.odt", PDF_LETTER)]).get_data(as_text=True)
    assert "Из PDF — проверить" not in page


def test_suspicious_value_from_pdf_is_not_preselected(client):
    """Отмечать подозрительное заранее — значит согласиться не глядя."""
    page = _upload(client, [("prilozhenie.pdf", PDF_LETTER)]).get_data(as_text=True)
    assert "checked" not in _checkbox(page, "micr0soft-update.com")


def test_clean_value_from_pdf_is_preselected(client):
    """К чистому значению вопросов нет — лишней работы аналитику не добавляем."""
    page = _upload(client, [("prilozhenie.pdf", PDF_LETTER)]).get_data(as_text=True)
    assert "checked" in _checkbox(page, "chistiy-domen.ru")


def test_pdf_row_shows_the_source_line(client):
    page = _upload(client, [("prilozhenie.pdf", PDF_LETTER)]).get_data(as_text=True)
    assert "micr0soft-update.com;" in page


def test_pdf_indicators_are_saved_normally_when_confirmed(client):
    """Вкладка меняет подачу, а не способ хранения."""
    from app.services.fstec.models import BlockEntry

    page = _upload(client, [("prilozhenie.pdf", PDF_LETTER)]).get_data(as_text=True)
    _save(client, ["0|chistiy-domen.ru"], _groups_json(page))
    assert BlockEntry.query.filter_by(value="chistiy-domen.ru").first() is not None
