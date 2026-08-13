"""Тесты каркаса портала: раскладка адресов и работа за прокси на подпути.

Снаружи портал отдаётся на подпути ``/soc/``, поэтому важно, чтобы ссылки
формировались с префиксом — иначе после первого же перехода пользователь
уходит в корень домена (там чужой сайт).
"""
import pytest
from cryptography.fernet import Fernet

from config import Config

from app import create_app
from app.core.extensions import db
from app.core.models import User, UserService
from app.portal import SERVICES


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    RPZ_FERNET_KEY = Fernet.generate_key().decode()
    BEHIND_PROXY = False


class ProxiedConfig(TestConfig):
    """Как на боевом сервере: за httpd на подпути /soc."""

    BEHIND_PROXY = True


PREFIX_HEADERS = {
    "X-Forwarded-Prefix": "/soc",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "soc-dashboards.72to.ru",
}


def _client(config):
    application = create_app(config)
    with application.app_context():
        db.create_all()
        user = User(username="op", role="admin")
        user.set_password("pass")
        db.session.add(user)
        db.session.flush()
        # Доступ к сервисам выдаёт администратор — без выдачи будет 403.
        for service in SERVICES:
            db.session.add(UserService(user_id=user.id, service_id=service.id))
        db.session.commit()
        client = application.test_client()
        client.post("/login", data={"username": "op", "password": "pass"})
        yield client


@pytest.fixture
def client():
    yield from _client(TestConfig)


@pytest.fixture
def proxied_client():
    yield from _client(ProxiedConfig)


# --- раскладка адресов ----------------------------------------------------

def test_portal_home_is_at_root(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Портал SOC" in response.get_data(as_text=True)


def test_fstec_service_lives_under_its_own_prefix(client):
    assert client.get("/fstec/").status_code == 200
    assert client.get("/fstec/push").status_code == 200


def test_skydns_service_lives_under_its_own_prefix(client):
    assert client.get("/skydns/").status_code == 200


def test_home_links_to_both_services(client):
    body = client.get("/").get_data(as_text=True)
    assert 'href="/fstec/"' in body
    assert 'href="/skydns/"' in body


def test_login_redirects_to_portal_home(client):
    fresh = client.application.test_client()
    response = fresh.post("/login", data={"username": "op", "password": "pass"})
    assert response.headers["Location"].endswith("/")
    assert "/fstec" not in response.headers["Location"]


def test_switcher_present_on_every_service(client):
    for path in ("/", "/fstec/", "/skydns/"):
        body = client.get(path).get_data(as_text=True)
        assert "РПЗ ФСТЭК" in body, path
        assert "Угрозы SkyDNS" in body, path


# --- работа за обратным прокси на подпути ---------------------------------

def test_links_carry_the_soc_prefix(proxied_client):
    body = proxied_client.get("/", headers=PREFIX_HEADERS).get_data(as_text=True)
    assert 'href="/soc/fstec/"' in body
    assert 'href="/soc/skydns/"' in body


def test_service_pages_keep_the_prefix(proxied_client):
    body = proxied_client.get("/skydns/domains",
                              headers=PREFIX_HEADERS).get_data(as_text=True)
    assert "/soc/skydns/" in body
    # Ссылок без префикса быть не должно — они увели бы в корень домена.
    assert 'href="/skydns/' not in body


def test_redirects_carry_the_prefix(proxied_client):
    response = proxied_client.post("/skydns/lookup-batch", headers=PREFIX_HEADERS)
    assert response.headers["Location"].startswith(
        ("/soc/", "https://soc-dashboards.72to.ru/soc/")
    ), response.headers["Location"]


def test_without_proxy_no_prefix_is_invented(client):
    """Заголовкам верим, только когда BEHIND_PROXY включён явно."""
    body = client.get("/", headers=PREFIX_HEADERS).get_data(as_text=True)
    assert 'href="/fstec/"' in body
    assert "/soc/" not in body


# --- возврат после действия не должен терять префикс -----------------------

def _make_task(client):
    client.post("/tasks/new", data={
        "title": "Проверить", "status": "backlog", "priority": "normal",
        "assignee_id": "0", "service_id": "", "submit": "1",
    }, headers=PREFIX_HEADERS, follow_redirects=False)
    from app.services.tasks.models import Task
    return Task.query.one()


def test_board_forms_carry_the_prefix_in_back_field(proxied_client):
    """Поле возврата — это адрес страницы, а он живёт под префиксом.

    request.full_path префикса не содержит, и подстановка его в форму
    отправляла браузер на /tasks/ мимо приложения — прямо в веб-сервер.
    """
    body = proxied_client.get("/tasks/", headers=PREFIX_HEADERS).get_data(as_text=True)
    assert 'name="back" value="/soc/tasks/' in body
    assert 'name="back" value="/tasks/' not in body


def test_move_returns_to_the_board_under_the_prefix(proxied_client):
    task = _make_task(proxied_client)
    response = proxied_client.post(
        f"/tasks/{task.id}/move",
        data={"status": "todo", "back": "/soc/tasks/"},
        headers=PREFIX_HEADERS,
    )
    assert response.headers["Location"].endswith("/soc/tasks/")


def test_stale_back_without_prefix_is_repaired(proxied_client):
    """Ссылка из открытой ранее вкладки могла прийти без префикса."""
    task = _make_task(proxied_client)
    response = proxied_client.post(
        f"/tasks/{task.id}/move",
        data={"status": "todo", "back": "/tasks/"},
        headers=PREFIX_HEADERS,
    )
    assert response.headers["Location"].endswith("/soc/tasks/")
    assert "/soc/soc/" not in response.headers["Location"]


def test_back_to_a_foreign_host_is_ignored(proxied_client):
    task = _make_task(proxied_client)
    response = proxied_client.post(
        f"/tasks/{task.id}/move",
        data={"status": "todo", "back": "//evil.example/phish"},
        headers=PREFIX_HEADERS,
    )
    assert "evil.example" not in response.headers["Location"]


def test_move_url_on_cards_carries_the_prefix(proxied_client):
    task = _make_task(proxied_client)
    body = proxied_client.get("/tasks/", headers=PREFIX_HEADERS).get_data(as_text=True)
    assert f'data-move-url="/soc/tasks/{task.id}/move"' in body


def test_quick_add_returns_under_the_prefix(proxied_client):
    response = proxied_client.post("/tasks/quick", data={
        "title": "Быстрая", "status": "todo", "assignee_id": "0",
        "priority": "normal", "back": "/soc/tasks/", "submit_quick": "1",
    }, headers=PREFIX_HEADERS)
    assert response.headers["Location"].endswith("/soc/tasks/")
