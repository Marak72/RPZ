"""Сервис «Задачи отдела»: доска, карточка, история и права."""
from datetime import date, timedelta

import pytest
from cryptography.fernet import Fernet

from config import Config

from app import create_app
from app.extensions import db
from app.models import ROLE_ADMIN, Task, TaskComment, TaskEvent, User, UserService
from app.portal import SERVICES


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    RPZ_FERNET_KEY = Fernet.generate_key().decode()


def _add_user(username, role="operator", grants=True) -> User:
    user = User(username=username, role=role)
    user.set_password("password123")
    db.session.add(user)
    db.session.flush()
    if grants:
        for service in SERVICES:
            db.session.add(UserService(user_id=user.id, service_id=service.id))
    db.session.commit()
    return user


@pytest.fixture
def app():
    application = create_app(TestConfig)
    with application.app_context():
        db.create_all()
        _add_user("boss", role=ROLE_ADMIN, grants=False)
        yield application


@pytest.fixture
def client(app):
    test_client = app.test_client()
    test_client.post("/login", data={"username": "boss", "password": "password123"})
    return test_client


def _create(client, **extra):
    data = {"title": "Заблокировать домены из письма 240/7",
            "status": "backlog", "priority": "normal",
            "assignee_id": "0", "service_id": "", "submit": "1"}
    data.update(extra)
    client.post("/tasks/new", data=data, follow_redirects=True)
    return Task.query.order_by(Task.id.desc()).first()


# --- создание и нумерация -------------------------------------------------

def test_task_gets_a_readable_key(client):
    task = _create(client)
    assert task.key == "SOC-1"
    assert task.reporter.username == "boss"


def test_numbers_increase_and_are_not_reused(client, app):
    first = _create(client, title="Первая")
    second = _create(client, title="Вторая")
    assert (first.number, second.number) == (1, 2)

    client.post(f"/tasks/{second.id}/delete", follow_redirects=True)
    third = _create(client, title="Третья")
    # Номер удалённой задачи не переиспользуется: на него могли ссылаться.
    assert third.number == 3


def test_creation_is_recorded_in_history(client):
    task = _create(client)
    events = TaskEvent.query.filter_by(task_id=task.id).all()
    assert [e.field for e in events] == ["created"]


def test_title_is_required(client):
    client.post("/tasks/new", data={"title": "", "status": "backlog",
                                    "priority": "normal", "assignee_id": "0",
                                    "submit": "1"}, follow_redirects=True)
    assert Task.query.count() == 0


# --- доска и фильтры ------------------------------------------------------

def test_board_shows_task_in_its_column(client):
    _create(client, title="Разобрать инцидент", status="in_progress")
    body = client.get("/tasks/").get_data(as_text=True)
    assert "Разобрать инцидент" in body
    assert "В работе" in body


def test_board_filters_by_assignee(client, app):
    user = _add_user("ivanov")
    _create(client, title="Моя", assignee_id=str(user.id))
    _create(client, title="Чужая")

    body = client.get(f"/tasks/?assignee={user.id}").get_data(as_text=True)
    assert "Моя" in body
    assert "Чужая" not in body


def test_board_filters_unassigned(client, app):
    user = _add_user("ivanov")
    _create(client, title="Назначенная", assignee_id=str(user.id))
    _create(client, title="Ничья")

    body = client.get("/tasks/?assignee=none").get_data(as_text=True)
    assert "Ничья" in body
    assert "Назначенная" not in body


def test_board_filters_overdue(client):
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    _create(client, title="Горит", due_date=yesterday)
    _create(client, title="Успеваем", due_date=tomorrow)

    body = client.get("/tasks/?overdue=1").get_data(as_text=True)
    assert "Горит" in body
    assert "Успеваем" not in body


def test_search_looks_into_description(client):
    _create(client, title="Задача", description="разобрать obltub.ru")
    assert "Задача" in client.get("/tasks/?q=obltub").get_data(as_text=True)


def test_done_tasks_hidden_from_the_list_by_default(client):
    _create(client, title="Свежая")
    _create(client, title="Закрытая", status="done")

    body = client.get("/tasks/list").get_data(as_text=True)
    assert "Свежая" in body
    assert "Закрытая" not in body
    # Но по вкладке статуса они находятся.
    assert "Закрытая" in client.get("/tasks/list?status=done").get_data(as_text=True)


# --- перенос, назначение, закрытие ---------------------------------------

def test_move_changes_status_and_writes_history(client):
    task = _create(client)
    client.post(f"/tasks/{task.id}/move", data={"status": "in_progress"},
                follow_redirects=True)

    updated = db.session.get(Task, task.id)
    assert updated.status == "in_progress"
    event = TaskEvent.query.filter_by(task_id=task.id, field="status").one()
    assert event.new_value == "В работе"


def test_unknown_status_is_rejected(client):
    task = _create(client)
    client.post(f"/tasks/{task.id}/move", data={"status": "нет-такого"},
                follow_redirects=True)
    assert db.session.get(Task, task.id).status == "backlog"


def test_closing_sets_and_reopening_clears_the_close_time(client):
    task = _create(client)
    client.post(f"/tasks/{task.id}/move", data={"status": "done"},
                follow_redirects=True)
    assert db.session.get(Task, task.id).closed_at is not None

    client.post(f"/tasks/{task.id}/move", data={"status": "todo"},
                follow_redirects=True)
    assert db.session.get(Task, task.id).closed_at is None


def test_take_it_and_drop_it(client, app):
    task = _create(client)
    boss = User.query.filter_by(username="boss").one()

    client.post(f"/tasks/{task.id}/assign", data={"assignee_id": str(boss.id)},
                follow_redirects=True)
    assert db.session.get(Task, task.id).assignee_id == boss.id

    client.post(f"/tasks/{task.id}/assign", data={"assignee_id": ""},
                follow_redirects=True)
    assert db.session.get(Task, task.id).assignee_id is None


def test_editing_logs_every_changed_field(client, app):
    user = _add_user("ivanov")
    task = _create(client)
    client.post(f"/tasks/{task.id}/edit", data={
        "title": "Новое название", "description": "подробности",
        "status": "review", "priority": "high",
        "assignee_id": str(user.id), "service_id": "fstec",
        "submit": "1",
    }, follow_redirects=True)

    changed = {e.field for e in TaskEvent.query.filter_by(task_id=task.id).all()}
    assert {"title", "description", "status", "priority", "assignee",
            "service"} <= changed


def test_unchanged_fields_do_not_pollute_history(client):
    task = _create(client)
    client.post(f"/tasks/{task.id}/edit", data={
        "title": task.title, "description": "", "status": "backlog",
        "priority": "normal", "assignee_id": "0", "service_id": "",
        "submit": "1",
    }, follow_redirects=True)
    fields = [e.field for e in TaskEvent.query.filter_by(task_id=task.id).all()]
    assert fields == ["created"]


# --- просроченность -------------------------------------------------------

def test_overdue_only_counts_open_tasks(client):
    yesterday = date.today() - timedelta(days=1)
    task = _create(client, due_date=yesterday.isoformat())
    assert db.session.get(Task, task.id).is_overdue is True

    client.post(f"/tasks/{task.id}/move", data={"status": "done"},
                follow_redirects=True)
    assert db.session.get(Task, task.id).is_overdue is False


# --- комментарии ----------------------------------------------------------

def test_comment_is_added(client):
    task = _create(client)
    client.post(f"/tasks/{task.id}", data={"body": "Взял в работу",
                                           "submit_comment": "1"},
                follow_redirects=True)
    comment = TaskComment.query.filter_by(task_id=task.id).one()
    assert comment.body == "Взял в работу"
    assert comment.user.username == "boss"


def test_empty_comment_is_rejected(client):
    task = _create(client)
    client.post(f"/tasks/{task.id}", data={"body": "  ", "submit_comment": "1"},
                follow_redirects=True)
    assert TaskComment.query.count() == 0


def test_deleting_task_removes_comments_and_history(client):
    task = _create(client)
    client.post(f"/tasks/{task.id}", data={"body": "Заметка",
                                           "submit_comment": "1"},
                follow_redirects=True)
    client.post(f"/tasks/{task.id}/delete", follow_redirects=True)

    assert Task.query.count() == 0
    assert TaskComment.query.count() == 0
    assert TaskEvent.query.count() == 0


# --- права ----------------------------------------------------------------

def test_viewer_cannot_change_anything(app):
    with app.app_context():
        _add_user("watcher", role="manager")
    viewer = app.test_client()
    viewer.post("/login", data={"username": "watcher", "password": "password123"})

    assert viewer.get("/tasks/").status_code == 200
    assert viewer.get("/tasks/new").status_code == 403
    assert viewer.post("/tasks/new", data={"title": "нельзя"}).status_code == 403


def test_service_is_closed_without_a_grant(app):
    with app.app_context():
        user = User(username="dns", role="operator")
        user.set_password("password123")
        db.session.add(user)
        db.session.flush()
        db.session.add(UserService(user_id=user.id, service_id="fstec"))
        db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "dns", "password": "password123"})
    assert client.get("/tasks/").status_code == 403


# --- экспорт --------------------------------------------------------------

def test_csv_export_contains_the_task(client):
    _create(client, title="Разобрать инцидент", priority="high")
    body = client.get("/tasks/tasks.csv").get_data(as_text=True)
    assert "SOC-1" in body
    assert "Разобрать инцидент" in body
    assert "Высокий" in body
