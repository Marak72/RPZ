"""Учётные записи сотрудников и разграничение доступа к сервисам."""
import pytest
from cryptography.fernet import Fernet

from config import Config

from app import create_app
from app.extensions import db
from app.models import ROLE_ADMIN, User, UserService
from app.portal import SERVICES


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    RPZ_FERNET_KEY = Fernet.generate_key().decode()


def _add_user(username, role="operator", services=(), enabled=True) -> User:
    user = User(username=username, role=role, is_enabled=enabled)
    user.set_password("password123")
    db.session.add(user)
    db.session.flush()
    for service_id in services:
        db.session.add(UserService(user_id=user.id, service_id=service_id))
    db.session.commit()
    return user


@pytest.fixture
def app():
    application = create_app(TestConfig)
    with application.app_context():
        db.create_all()
        _add_user("boss", role=ROLE_ADMIN)
        yield application


@pytest.fixture
def admin(app):
    client = app.test_client()
    client.post("/login", data={"username": "boss", "password": "password123"})
    return client


def _login(app, username):
    client = app.test_client()
    client.post("/login", data={"username": username, "password": "password123"})
    return client


# --- доступ к сервисам ----------------------------------------------------

def test_admin_sees_every_service_without_grants(admin):
    """Администратору сервисы не выдают — они доступны по роли."""
    assert admin.get("/fstec/").status_code == 200
    assert admin.get("/skydns/").status_code == 200


def test_user_without_grants_is_blocked(app):
    _add_user("newbie")
    client = _login(app, "newbie")
    assert client.get("/").status_code == 200          # главная доступна всем
    assert client.get("/fstec/").status_code == 403
    assert client.get("/skydns/").status_code == 403


def test_granted_service_opens_and_other_stays_closed(app):
    _add_user("dns", services=["fstec"])
    client = _login(app, "dns")
    assert client.get("/fstec/").status_code == 200
    assert client.get("/skydns/").status_code == 403


def test_guard_covers_inner_pages_not_just_the_entry(app):
    """Права проверяются на весь blueprint, а не только на главную сервиса."""
    _add_user("dns", services=["fstec"])
    client = _login(app, "dns")
    for path in ("/skydns/domains", "/skydns/hosts", "/skydns/sync",
                 "/skydns/settings", "/skydns/domains.csv"):
        assert client.get(path).status_code == 403, path


def test_switcher_hides_services_without_access(app):
    _add_user("dns", services=["fstec"])
    body = _login(app, "dns").get("/").get_data(as_text=True)
    assert "РПЗ ФСТЭК" in body
    assert "Угрозы SkyDNS" not in body


def test_admin_area_is_closed_for_ordinary_users(app):
    _add_user("dns", services=["fstec"])
    client = _login(app, "dns")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/users/new").status_code == 403


def test_profile_is_open_to_everyone(app):
    _add_user("dns", services=["fstec"])
    assert _login(app, "dns").get("/admin/profile").status_code == 200


def test_profile_switcher_hides_services_without_access(app):
    """Переключатель на профиле показывает то же, что и везде."""
    _add_user("dns", services=["fstec"])
    body = _login(app, "dns").get("/admin/profile").get_data(as_text=True)
    assert "РПЗ ФСТЭК" in body
    assert "Угрозы SkyDNS" not in body


# --- вход -----------------------------------------------------------------

def test_disabled_account_cannot_log_in(app):
    _add_user("fired", services=["fstec"], enabled=False)
    client = app.test_client()
    response = client.post("/login",
                           data={"username": "fired", "password": "password123"},
                           follow_redirects=True)
    assert "отключена" in response.get_data(as_text=True)
    assert client.get("/fstec/").status_code != 200


def test_login_records_the_time(app, admin):
    user = User.query.filter_by(username="boss").one()
    assert user.last_login_at is not None


# --- управление учётными записями -----------------------------------------

def test_admin_creates_user_with_selected_services(admin, app):
    admin.post("/admin/users/new", data={
        "username": "ivanov", "full_name": "Иванов Иван",
        "role": "operator", "services": ["skydns"],
        "is_enabled": "y",
        "password": "password123", "password2": "password123",
        "submit": "1",
    }, follow_redirects=True)

    user = User.query.filter_by(username="ivanov").one()
    assert user.full_name == "Иванов Иван"
    assert user.allowed_services() == {"skydns"}
    assert user.check_password("password123")


def test_new_user_requires_a_password(admin):
    admin.post("/admin/users/new", data={
        "username": "nopass", "role": "operator", "services": ["fstec"],
        "submit": "1",
    }, follow_redirects=True)
    assert User.query.filter_by(username="nopass").first() is None


def test_duplicate_login_is_rejected(admin, app):
    _add_user("ivanov")
    admin.post("/admin/users/new", data={
        "username": "ivanov", "role": "operator",
        "password": "password123", "password2": "password123",
        "submit": "1",
    }, follow_redirects=True)
    assert User.query.filter_by(username="ivanov").count() == 1


def test_editing_replaces_the_grant_list(admin, app):
    user = _add_user("ivanov", services=["fstec", "skydns"])
    admin.post(f"/admin/users/{user.id}", data={
        "username": "ivanov", "role": "operator", "services": ["fstec"],
        "is_enabled": "y", "submit": "1",
    }, follow_redirects=True)
    assert User.query.filter_by(username="ivanov").one().allowed_services() == {"fstec"}


def test_editing_without_password_keeps_the_old_one(admin, app):
    user = _add_user("ivanov", services=["fstec"])
    admin.post(f"/admin/users/{user.id}", data={
        "username": "ivanov", "role": "manager", "services": ["fstec"],
        "is_enabled": "y", "submit": "1",
    }, follow_redirects=True)
    updated = User.query.filter_by(username="ivanov").one()
    assert updated.role == "manager"
    assert updated.check_password("password123")


def test_toggle_disables_and_enables(admin, app):
    user = _add_user("ivanov", services=["fstec"])
    admin.post(f"/admin/users/{user.id}/toggle", follow_redirects=True)
    assert User.query.filter_by(username="ivanov").one().is_enabled is False
    admin.post(f"/admin/users/{user.id}/toggle", follow_redirects=True)
    assert User.query.filter_by(username="ivanov").one().is_enabled is True


def test_delete_removes_the_account(admin, app):
    user = _add_user("ivanov")
    admin.post(f"/admin/users/{user.id}/delete", follow_redirects=True)
    assert User.query.filter_by(username="ivanov").first() is None


# --- страховки от самоблокировки ------------------------------------------

def test_admin_cannot_disable_themselves(admin, app):
    boss = User.query.filter_by(username="boss").one()
    admin.post(f"/admin/users/{boss.id}/toggle", follow_redirects=True)
    assert User.query.filter_by(username="boss").one().is_enabled is True


def test_admin_cannot_delete_themselves(admin, app):
    boss = User.query.filter_by(username="boss").one()
    admin.post(f"/admin/users/{boss.id}/delete", follow_redirects=True)
    assert User.query.filter_by(username="boss").first() is not None


def test_admin_cannot_drop_their_own_admin_role(admin, app):
    """Иначе в портале не останется никого, кто заводит учётные записи."""
    boss = User.query.filter_by(username="boss").one()
    admin.post(f"/admin/users/{boss.id}", data={
        "username": "boss", "role": "operator", "is_enabled": "y", "submit": "1",
    }, follow_redirects=True)
    assert User.query.filter_by(username="boss").one().role == ROLE_ADMIN


def test_last_admin_cannot_be_demoted(admin, app):
    """Второго администратора нет — понижать единственного нельзя."""
    other = _add_user("second", role=ROLE_ADMIN)
    # Пока администраторов двое, понижение проходит.
    admin.post(f"/admin/users/{other.id}", data={
        "username": "second", "role": "operator", "is_enabled": "y", "submit": "1",
    }, follow_redirects=True)
    assert User.query.filter_by(username="second").one().role == "operator"


# --- профиль --------------------------------------------------------------

def test_user_changes_own_password(app):
    _add_user("ivanov", services=["fstec"])
    client = _login(app, "ivanov")
    client.post("/admin/profile", data={
        "current": "password123", "password": "newpassword1",
        "password2": "newpassword1", "submit_password": "1",
    }, follow_redirects=True)
    assert User.query.filter_by(username="ivanov").one().check_password(
        "newpassword1"
    )


def test_wrong_current_password_is_rejected(app):
    _add_user("ivanov", services=["fstec"])
    client = _login(app, "ivanov")
    client.post("/admin/profile", data={
        "current": "wrong", "password": "newpassword1",
        "password2": "newpassword1", "submit_password": "1",
    }, follow_redirects=True)
    assert User.query.filter_by(username="ivanov").one().check_password(
        "password123"
    )


def test_profile_saves_own_details(app):
    _add_user("ivanov", services=["fstec"])
    client = _login(app, "ivanov")
    client.post("/admin/profile", data={
        "full_name": "Иванов Иван", "position": "аналитик",
        "email": "ivanov@72to.ru", "submit_profile": "1",
    }, follow_redirects=True)
    user = User.query.filter_by(username="ivanov").one()
    assert user.full_name == "Иванов Иван"
    assert user.email == "ivanov@72to.ru"


# --- роли -----------------------------------------------------------------

def test_admin_counts_as_operator(app):
    """Администратор должен уметь всё, что оператор."""
    boss = User.query.filter_by(username="boss").one()
    assert boss.is_operator is True
    assert boss.is_admin is True


def test_manager_is_not_an_operator(app):
    user = _add_user("watcher", role="manager", services=list(
        svc.id for svc in SERVICES
    ))
    assert user.is_operator is False
    client = _login(app, "watcher")
    # Просмотр открыт, изменение — нет.
    assert client.get("/skydns/domains").status_code == 200
    assert client.post("/skydns/lookup-batch").status_code == 403
