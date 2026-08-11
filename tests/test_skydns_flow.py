"""Интеграционные тесты сервиса «Угрозы SkyDNS».

Внешние системы заменены заглушками: проверяется цепочка от загрузки
статистики до передачи домена в кандидаты на блокировку RPZ.
"""
import io

import pytest
from cryptography.fernet import Fernet

from config import Config  # noqa: E402

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import (  # noqa: E402
    BlockEntry,
    SiemQueryLog,
    SkydnsCategory,
    ThreatDomain,
    ThreatHost,
    User,
    UserService,
)
from app.portal import SERVICES  # noqa: E402
from app.services.siem_client import HostHit, SearchResult, SiemError  # noqa: E402
from app.skydns import routes as skydns_routes  # noqa: E402


class FakeSiemClient:
    """Заглушка SIEM: отдаёт заранее заданные хосты или падает."""

    instances = []

    def __init__(self, config):
        self.config = config
        self.closed = False
        self.searched = []
        FakeSiemClient.instances.append(self)

    login_error = None
    search_error = None
    hits = ()

    def login(self):
        if FakeSiemClient.login_error:
            raise SiemError(FakeSiemClient.login_error)

    def search_hosts(self, domain, time_from, time_to, filter_template, group_field):
        self.searched.append(domain)
        if FakeSiemClient.search_error:
            raise SiemError(FakeSiemClient.search_error)
        return SearchResult(
            hosts=[HostHit(address=a, events_count=c) for a, c in FakeSiemClient.hits],
            total_count=sum(c for _, c in FakeSiemClient.hits),
            query_filter=filter_template.replace("{domain}", domain),
        )

    def close(self):
        self.closed = True


class TestConfig(Config):
    """База в памяти: тесты не должны трогать рабочий instance/rpz.db."""

    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    RPZ_FERNET_KEY = Fernet.generate_key().decode()


@pytest.fixture
def app(monkeypatch):
    application = create_app(TestConfig)
    FakeSiemClient.instances = []
    FakeSiemClient.login_error = None
    FakeSiemClient.search_error = None
    FakeSiemClient.hits = (("10.0.12.34", 17), ("10.0.12.99", 3))
    monkeypatch.setattr(skydns_routes, "SiemClient", FakeSiemClient)

    with application.app_context():
        db.create_all()
        user = User(username="op", role="operator")
        user.set_password("pass")
        db.session.add(user)
        db.session.flush()
        _grant_all(user)
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    test_client = app.test_client()
    test_client.post("/login", data={"username": "op", "password": "pass"})
    return test_client


def _grant_all(user: User) -> None:
    """Выдать сотруднику все сервисы портала.

    Без явной выдачи blueprint сервиса отдаёт 403 — доступ разграничивается
    администратором.
    """
    for service in SERVICES:
        db.session.add(UserService(user_id=user.id, service_id=service.id))


def _add_threat(domain="obltub.ru", category="malware") -> int:
    threat = ThreatDomain(domain=domain, category=category)
    db.session.add(threat)
    db.session.commit()
    return threat.id


# --- загрузка статистики --------------------------------------------------

def test_csv_import_saves_domains(client):
    """CSV — запасной путь: категорию фильтровать нечем, сохраняем всё."""
    data = (
        "domain;category;requests\r\n"
        "evil.ru;malware;42\r\n"
    ).encode("utf-8")
    response = client.post(
        "/skydns/sync",
        data={"report": (io.BytesIO(data), "stat.csv"), "submit_import": "1"},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    threat = ThreatDomain.query.filter_by(domain="evil.ru").one()
    assert threat.requests_count == 42
    assert threat.category_title == "malware"


def test_api_sync_keeps_only_tracked_categories(client, monkeypatch):
    """Домен вне отслеживаемых категорий в разбор не попадает."""
    from app.services.skydns_client import Category, DomainStat

    class FakeSkydns:
        def __init__(self, config):
            pass

        def categories(self, start, end, lang="ru"):
            return [Category(3, "Malware", True),
                    Category(49, "Computers & Internet", False)]

        def domains(self, start, end, cats=None, limit=None, order_by="-visits"):
            FakeSkydns.asked_cats = cats
            return [
                DomainStat("evil.ru", requests=42, blocks=40, cat_ids=[3]),
                DomainStat("news.ru", requests=900, blocks=0, cat_ids=[49]),
            ]

        def hosts_by_domain(self, start, end, cats=None, limit=None):
            return {}

    monkeypatch.setattr(skydns_routes, "SkydnsClient", FakeSkydns)
    response = client.post("/skydns/sync", data={
        "start": "2026-08-01", "end": "2026-08-07", "submit_sync": "1",
    }, follow_redirects=True)
    assert response.status_code == 200

    # В запрос ушёл фильтр по опасным категориям из ответа API.
    assert FakeSkydns.asked_cats == [3]
    domains = {t.domain for t in ThreatDomain.query.all()}
    assert domains == {"evil.ru"}, "обычная категория не должна попадать в разбор"

    threat = ThreatDomain.query.filter_by(domain="evil.ru").one()
    assert threat.category_title == "Malware"
    assert threat.cat_ids == "3"
    # Справочник категорий сохранён целиком, включая неопасные.
    assert SkydnsCategory.query.count() == 2


def test_api_sync_saves_devices_as_hosts(client, monkeypatch):
    """Устройства с агентом SkyDNS становятся хостами без обращения к SIEM."""
    from app.services.skydns_client import Category, DeviceStat, DomainStat

    class FakeSkydns:
        def __init__(self, config):
            pass

        def categories(self, start, end, lang="ru"):
            return [Category(3, "Malware", True)]

        def domains(self, start, end, cats=None, limit=None, order_by="-visits"):
            return [DomainStat("evil.ru", requests=42, cat_ids=[3])]

        def hosts_by_domain(self, start, end, cats=None, limit=None):
            # Записи шлюза (token = 0) сюда уже не попадают: их отсеивает
            # сам клиент при разборе детализации.
            return {"evil.ru": [
                DeviceStat(token=12345678, ipv4=["10.0.1.5"], requests=17),
            ]}

    monkeypatch.setattr(skydns_routes, "SkydnsClient", FakeSkydns)
    client.post("/skydns/sync", data={
        "start": "2026-08-01", "end": "2026-08-07", "submit_sync": "1",
    }, follow_redirects=True)

    hosts = ThreatHost.query.all()
    assert [h.address for h in hosts] == ["10.0.1.5"]
    assert hosts[0].source == "skydns"
    assert hosts[0].device_token == "12345678"
    assert hosts[0].events_count == 17


def test_siem_hosts_are_marked_with_their_source(client):
    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/lookup", follow_redirects=True)
    assert {h.source for h in ThreatHost.query.all()} == {"siem"}


def test_manual_add_skips_category_check(client):
    client.post("/skydns/sync", data={
        "values": "internal-suspect.ru", "category": "ручной разбор",
        "submit_manual": "1",
    }, follow_redirects=True)
    assert ThreatDomain.query.filter_by(domain="internal-suspect.ru").first()


# --- поиск хостов в SIEM --------------------------------------------------

def test_lookup_saves_hosts_and_log(client):
    threat_id = _add_threat()
    response = client.post(f"/skydns/domains/{threat_id}/lookup",
                           follow_redirects=True)
    assert response.status_code == 200

    threat = db.session.get(ThreatDomain, threat_id)
    assert threat.siem_hosts_count == 2
    assert threat.siem_checked_at is not None
    assert {h.address for h in threat.hosts} == {"10.0.12.34", "10.0.12.99"}

    log = SiemQueryLog.query.filter_by(threat_id=threat_id).one()
    assert log.status == "success"
    assert log.hosts_found == 2
    assert log.events_total == 20
    # Фильтр сохраняется целиком, чтобы запрос можно было повторить руками.
    assert 'datafield1 = "obltub.ru"' in log.query_filter


def test_lookup_closes_siem_session(client):
    _add_threat()
    client.post("/skydns/lookup-batch", follow_redirects=True)
    assert FakeSiemClient.instances[-1].closed is True


def test_repeated_lookup_merges_hosts(client):
    """Результаты прошлых проверок не теряются при новом запросе."""
    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/lookup", follow_redirects=True)

    FakeSiemClient.hits = (("10.0.12.34", 25), ("10.0.55.1", 4))
    client.post(f"/skydns/domains/{threat_id}/lookup", follow_redirects=True)

    threat = db.session.get(ThreatDomain, threat_id)
    assert {h.address for h in threat.hosts} == {
        "10.0.12.34", "10.0.12.99", "10.0.55.1"
    }
    updated = threat.hosts.filter_by(address="10.0.12.34").one()
    assert updated.events_count == 25


def test_batch_lookup_logs_in_once_for_all_domains(client):
    _add_threat("a-evil.ru")
    _add_threat("b-evil.ru")
    client.post("/skydns/lookup-batch", follow_redirects=True)
    assert len(FakeSiemClient.instances) == 1
    assert sorted(FakeSiemClient.instances[0].searched) == ["a-evil.ru", "b-evil.ru"]


def test_batch_lookup_skips_already_checked_domains(client):
    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/lookup", follow_redirects=True)
    client.post("/skydns/lookup-batch", follow_redirects=True)
    # Второй вход в SIEM не создавался: проверять было нечего.
    assert len(FakeSiemClient.instances) == 1


def test_login_failure_is_logged_for_every_domain(client):
    _add_threat("a-evil.ru")
    _add_threat("b-evil.ru")
    FakeSiemClient.login_error = "SIEM отклонил вход (401)."

    response = client.post("/skydns/lookup-batch", follow_redirects=True)
    assert response.status_code == 200

    logs = SiemQueryLog.query.all()
    assert len(logs) == 2
    assert all(log.status == "failed" for log in logs)
    assert all("401" in log.message for log in logs)
    assert ThreatHost.query.count() == 0


def test_search_failure_does_not_mark_domain_checked(client):
    threat_id = _add_threat()
    FakeSiemClient.search_error = "Некорректный PDQL"
    client.post(f"/skydns/domains/{threat_id}/lookup", follow_redirects=True)

    threat = db.session.get(ThreatDomain, threat_id)
    assert threat.siem_checked_at is None
    assert SiemQueryLog.query.one().status == "failed"


# --- передача в блокировку RPZ --------------------------------------------

def test_to_rpz_creates_candidate(client):
    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/to-rpz", follow_redirects=True)

    entry = BlockEntry.query.filter_by(value="obltub.ru").one()
    assert entry.entry_type == "domain"
    assert entry.source == "skydns"
    assert entry.status == "new"
    assert db.session.get(ThreatDomain, threat_id).status == "blocked"


def test_to_rpz_is_idempotent(client):
    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/to-rpz", follow_redirects=True)
    client.post(f"/skydns/domains/{threat_id}/to-rpz", follow_redirects=True)
    assert BlockEntry.query.filter_by(value="obltub.ru").count() == 1


# --- удаление и возврат по referrer ---------------------------------------

def test_delete_removes_domain_with_its_hosts(client):
    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/lookup", follow_redirects=True)
    assert ThreatHost.query.count() == 2

    client.post(f"/skydns/domains/{threat_id}/delete", follow_redirects=True)
    assert ThreatDomain.query.count() == 0
    assert ThreatHost.query.count() == 0
    # Журнал переживает удаление домена — история запросов не теряется.
    assert SiemQueryLog.query.count() == 1


def test_batch_lookup_returns_to_local_referrer(client):
    _add_threat()
    response = client.post("/skydns/lookup-batch",
                           headers={"Referer": "/skydns/domains?status=new"})
    assert response.headers["Location"].endswith("/skydns/domains?status=new")


def test_batch_lookup_ignores_external_referrer(client):
    """Referrer приходит от браузера — уводить по нему наружу нельзя."""
    _add_threat()
    response = client.post("/skydns/lookup-batch",
                           headers={"Referer": "https://evil.example/phish"})
    assert "evil.example" not in response.headers["Location"]
    assert response.headers["Location"].endswith("/skydns/domains")


# --- права доступа --------------------------------------------------------

def test_manager_cannot_run_lookup(app):
    with app.app_context():
        manager = User(username="mgr", role="manager")
        manager.set_password("pass")
        db.session.add(manager)
        db.session.flush()
        _grant_all(manager)
        threat_id = _add_threat()
        db.session.commit()

    viewer = app.test_client()
    viewer.post("/login", data={"username": "mgr", "password": "pass"})
    response = viewer.post(f"/skydns/domains/{threat_id}/lookup")
    assert response.status_code == 403
    assert SiemQueryLog.query.count() == 0


# --- категории угроз и лимит выборки --------------------------------------

def _fake_skydns(monkeypatch, cats, domains, hosts=None):
    from app.services.skydns_client import Category, DomainStat  # noqa: F401

    class FakeSkydns:
        def __init__(self, config):
            pass

        def categories(self, start, end, lang="ru"):
            return cats

        def domains(self, start, end, cats=None, limit=None, order_by="-visits"):
            FakeSkydns.limit = limit
            return domains

        def hosts_by_domain(self, start, end, cats=None, limit=None):
            return hosts or {}

    monkeypatch.setattr(skydns_routes, "SkydnsClient", FakeSkydns)
    return FakeSkydns


def _sync(client):
    return client.post("/skydns/sync", data={
        "start": "2026-08-01", "end": "2026-08-07", "submit_sync": "1",
    }, follow_redirects=True)


def test_category_counters_are_saved(client, monkeypatch):
    """Счётчики по категориям нужны, чтобы видеть, откуда идёт поток."""
    from app.services.skydns_client import Category, DomainStat

    _fake_skydns(
        monkeypatch,
        [Category(73, "DNS-туннелирование", True, requests=24563, blocks=0),
         Category(3, "Malware", True, requests=294, blocks=0)],
        [DomainStat("evil.ru", requests=42, cat_ids=[3])],
    )
    _sync(client)

    tunnel = db.session.get(SkydnsCategory, 73)
    assert tunnel.requests == 24563
    assert tunnel.is_dangerous is True
    # Доменов в этой категории не набралось — счётчик честно нулевой.
    assert tunnel.domains_count == 0
    assert db.session.get(SkydnsCategory, 3).domains_count == 1


def test_dashboard_shows_threat_categories(client, monkeypatch):
    from app.services.skydns_client import Category, DomainStat

    _fake_skydns(
        monkeypatch,
        [Category(73, "DNS-туннелирование", True, requests=24563)],
        [DomainStat("evil.ru", requests=42, cat_ids=[73])],
    )
    _sync(client)

    body = client.get("/skydns/").get_data(as_text=True)
    assert "Категории угроз" in body
    assert "DNS-туннелирование" in body
    assert "24 563" in body


def test_hitting_the_limit_is_reported(client, monkeypatch):
    """Упор в лимит нельзя проглатывать: часть доменов осталась в SkyDNS."""
    from app.models import BackgroundJob
    from app.services.skydns_client import Category, DomainStat

    fake = _fake_skydns(
        monkeypatch,
        [Category(3, "Malware", True)],
        [DomainStat(f"evil{i}.ru", requests=i, cat_ids=[3]) for i in range(2000)],
    )
    _sync(client)

    assert fake.limit == 2000
    assert "Упёрлись в лимит" in BackgroundJob.query.one().message


def test_no_limit_warning_when_everything_fits(client, monkeypatch):
    from app.services.skydns_client import Category, DomainStat

    _fake_skydns(monkeypatch, [Category(3, "Malware", True)],
                 [DomainStat("evil.ru", requests=1, cat_ids=[3])])
    assert "упёрлась в лимит" not in _sync(client).get_data(as_text=True)


def test_category_filter_matches_every_category_of_a_domain(client, monkeypatch):
    """Домен часто относится к нескольким категориям — искать надо по всем."""
    from app.services.skydns_client import Category, DomainStat

    _fake_skydns(
        monkeypatch,
        [Category(3, "Malware", True), Category(4, "Phishing", True)],
        [DomainStat("evil.ru", requests=5, cat_ids=[3, 4])],
    )
    _sync(client)

    # Основная категория — первая опасная, но по второй домен тоже находится.
    assert "evil.ru" in client.get("/skydns/domains?category=3").get_data(as_text=True)
    assert "evil.ru" in client.get("/skydns/domains?category=4").get_data(as_text=True)
    assert "evil.ru" not in client.get(
        "/skydns/domains?category=99").get_data(as_text=True)


def test_category_filter_shows_titles_not_ids(client, monkeypatch):
    from app.services.skydns_client import Category, DomainStat

    _fake_skydns(monkeypatch, [Category(3, "Malware", True)],
                 [DomainStat("evil.ru", requests=1, cat_ids=[3])])
    _sync(client)

    body = client.get("/skydns/domains").get_data(as_text=True)
    assert '<option value="3"' in body
    assert ">Malware</option>" in body


# --- поиск в SIEM идёт в фоне ---------------------------------------------

def test_lookup_returns_immediately_and_creates_a_job(client):
    """Страница не должна ждать SIEM: работа уходит в фоновое задание."""
    from app.models import JOB_KIND_SIEM, BackgroundJob

    threat_id = _add_threat()
    response = client.post(f"/skydns/domains/{threat_id}/lookup")
    assert response.status_code == 302

    job = BackgroundJob.query.one()
    assert job.kind == JOB_KIND_SIEM
    assert job.service_id == "skydns"
    assert job.total == 1
    assert "obltub.ru" in job.title


def test_job_summary_counts_domains_and_hosts(client):
    from app.models import BackgroundJob

    _add_threat("a-evil.ru")
    _add_threat("b-evil.ru")
    client.post("/skydns/lookup-batch")

    job = BackgroundJob.query.one()
    assert "Проверено доменов: 2" in job.message
    assert "Найдено хостов: 4" in job.message


def test_second_lookup_is_refused_while_the_first_runs(client):
    """Два поиска разом только поделят между собой и без того небыстрый SIEM."""
    from datetime import datetime

    from app.models import JOB_KIND_SIEM, JOB_RUNNING, BackgroundJob

    db.session.add(BackgroundJob(
        kind=JOB_KIND_SIEM, status=JOB_RUNNING, title="идёт",
        heartbeat_at=datetime.utcnow(),
    ))
    db.session.commit()

    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/lookup")

    # Новое задание не заведено, домен остался непроверенным.
    assert BackgroundJob.query.count() == 1
    assert db.session.get(ThreatDomain, threat_id).siem_checked_at is None


def test_empty_result_points_to_the_probe_page(client):
    """Ноль хостов чаще означает не «никто не ходил», а промах по полю."""
    from app.models import BackgroundJob

    FakeSiemClient.hits = ()
    _add_threat()
    client.post("/skydns/lookup-batch")

    assert "Диагностика" in BackgroundJob.query.one().message


def test_login_failure_marks_the_job_as_failed(client):
    from app.models import JOB_FAILED, BackgroundJob

    FakeSiemClient.login_error = "SIEM отклонил вход (401)."
    _add_threat()
    client.post("/skydns/lookup-batch")

    job = BackgroundJob.query.one()
    assert job.status == JOB_FAILED
    assert "401" in job.message
