"""Тесты работы с письмами ФСТЭК: множественная загрузка и выгрузка CSV."""
import io

import pytest
from cryptography.fernet import Fernet

from config import Config

from app import create_app
from app.extensions import db
from app.main import routes as main_routes
from app.models import (
    BlockEntry,
    Document,
    IocHash,
    UrlEntry,
    User,
    UserService,
)
from app.portal import SERVICES
from app.services import doc_parser

# Минимальное письмо: индикаторы на отдельных строках — так их видит парсер.
LETTER_A = """Приложение к письму ФСТЭК России

evil-alpha.ru
203.0.113.10
"""

LETTER_B = """Приложение 2

evil-beta.ru
198.51.100.7
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
    # Здесь проверяется привязка индикаторов к файлам, а не сам парсер, поэтому
    # текст берётся из файла напрямую.
    monkeypatch.setattr(
        main_routes.doc_parser, "extract_from_file",
        lambda filename, data: doc_parser.extract(data.decode("utf-8")),
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


def _save(client, values, files_json, **extra):
    data = {"selected": values, "files_json": files_json}
    data.update(extra)
    return client.post("/fstec/preview", data=data, follow_redirects=True)


def _files_json(page: str) -> str:
    """Достать скрытое поле files_json со страницы предпросмотра."""
    marker = 'name="files_json" value="'
    start = page.index(marker) + len(marker)
    end = page.index('"', start)
    return page[start:end].replace("&#34;", '"').replace("&amp;", "&")


# --- множественная загрузка ----------------------------------------------

def test_single_file_still_works(client):
    page = _upload(client, [("letter.odt", LETTER_A.encode())])
    assert page.status_code == 200
    assert "evil-alpha.ru" in page.get_data(as_text=True)


def test_two_files_are_parsed_together(client):
    page = _upload(client, [
        ("letter1.odt", LETTER_A.encode()),
        ("letter2.odt", LETTER_B.encode()),
    ]).get_data(as_text=True)

    assert "evil-alpha.ru" in page
    assert "evil-beta.ru" in page
    # На предпросмотре видно, из какого файла пришёл индикатор.
    assert "letter1.odt" in page
    assert "letter2.odt" in page


def test_each_file_becomes_its_own_letter(client):
    page = _upload(client, [
        ("letter1.odt", LETTER_A.encode()),
        ("letter2.odt", LETTER_B.encode()),
    ]).get_data(as_text=True)
    files_json = _files_json(page)

    _save(client, ["0|evil-alpha.ru", "1|evil-beta.ru"], files_json,
          letter_number="240/1", letter_date="2026-08-01")

    docs = Document.query.order_by(Document.filename).all()
    assert [d.filename for d in docs] == ["letter1.odt", "letter2.odt"]
    # Реквизиты письма применяются ко всей пачке.
    assert {d.letter_number for d in docs} == {"240/1"}

    alpha = BlockEntry.query.filter_by(value="evil-alpha.ru").one()
    beta = BlockEntry.query.filter_by(value="evil-beta.ru").one()
    assert alpha.document.filename == "letter1.odt"
    assert beta.document.filename == "letter2.odt"
    # Счётчик найденного считается по каждому письму отдельно.
    assert {d.entries_found for d in docs} == {1}


def test_duplicate_indicator_across_files_shown_once(client):
    page = _upload(client, [
        ("a.odt", LETTER_A.encode()),
        ("b.odt", LETTER_A.encode()),
    ]).get_data(as_text=True)
    assert page.count('value="0|evil-alpha.ru"') == 1
    assert 'value="1|evil-alpha.ru"' not in page


def test_upload_without_files_is_rejected(client):
    response = client.post("/fstec/upload", data={"submit": "1"},
                           content_type="multipart/form-data")
    assert response.status_code == 200
    assert "Выберите хотя бы один файл" in response.get_data(as_text=True)
    assert Document.query.count() == 0


def test_save_without_files_json_does_not_create_letters(client):
    response = client.post("/fstec/preview", data={"selected": ["0|evil.ru"]},
                           follow_redirects=True)
    assert response.status_code == 200
    assert Document.query.count() == 0
    assert BlockEntry.query.count() == 0


# --- выгрузка CSV ---------------------------------------------------------

def _letter_with_indicators(client):
    page = _upload(client, [("letter.odt", LETTER_A.encode())],
                   letter_number="240/7", letter_date="2026-08-01")
    files_json = _files_json(page.get_data(as_text=True))
    _save(client, ["0|evil-alpha.ru", "0|203.0.113.10"], files_json,
          letter_number="240/7", letter_date="2026-08-01")
    return Document.query.one()


def test_letter_csv_contains_its_indicators(client):
    doc = _letter_with_indicators(client)
    response = client.get(f"/fstec/letters/{doc.id}.csv")
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    assert "evil-alpha.ru" in body
    assert "203.0.113.10" in body
    # Реквизиты письма едут вместе с индикаторами.
    assert "240/7" in body
    assert "01.08.2026" in body


def test_letter_csv_is_a_download_with_bom(client):
    doc = _letter_with_indicators(client)
    response = client.get(f"/fstec/letters/{doc.id}.csv")
    assert "attachment" in response.headers["Content-Disposition"]
    # BOM — иначе Excel в русской локали ломает кодировку.
    assert response.get_data().startswith("﻿".encode())


def test_letter_csv_covers_urls_and_hashes(client, app):
    doc = _letter_with_indicators(client)
    db.session.add(UrlEntry(value="http://evil-alpha.ru/x.php",
                            host="evil-alpha.ru", document_id=doc.id))
    db.session.add(IocHash(value="a" * 64, hash_type="sha256",
                           document_id=doc.id))
    db.session.commit()

    body = client.get(f"/fstec/letters/{doc.id}.csv").get_data(as_text=True)
    assert "http://evil-alpha.ru/x.php" in body
    assert "a" * 64 in body
    assert "sha256" in body


def test_all_letters_csv_lists_every_letter(client):
    page = _upload(client, [
        ("letter1.odt", LETTER_A.encode()),
        ("letter2.odt", LETTER_B.encode()),
    ]).get_data(as_text=True)
    _save(client, ["0|evil-alpha.ru", "1|evil-beta.ru"], _files_json(page))

    body = client.get("/fstec/letters.csv").get_data(as_text=True)
    assert "evil-alpha.ru" in body
    assert "evil-beta.ru" in body
    assert "letter1.odt" in body
    assert "letter2.odt" in body


def test_letter_csv_404_for_unknown_letter(client):
    assert client.get("/fstec/letters/9999.csv").status_code == 404


# --- источник в выгрузке --------------------------------------------------

def test_push_view_links_source_to_its_letter(client):
    doc = _letter_with_indicators(client)
    body = client.get("/fstec/push").get_data(as_text=True)
    # Источник — ссылка на письмо, а не просто имя файла.
    assert f"/fstec/letters/{doc.id}" in body
    assert "240/7" in body
