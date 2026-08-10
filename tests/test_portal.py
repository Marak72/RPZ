"""Тесты каркаса портала: раскладка адресов и работа за прокси на подпути.

Снаружи портал отдаётся на подпути ``/soc/``, поэтому важно, чтобы ссылки
формировались с префиксом — иначе после первого же перехода пользователь
уходит в корень домена (там чужой сайт).
"""
import pytest
from cryptography.fernet import Fernet

from config import Config

from app import create_app
from app.extensions import db
from app.models import User


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
        user = User(username="op", role="operator")
        user.set_password("pass")
        db.session.add(user)
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
