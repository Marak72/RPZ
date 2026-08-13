"""Интеграционные тесты сервиса «Угрозы SkyDNS».

Внешние системы заменены заглушками: проверяется цепочка от загрузки
статистики до передачи домена в кандидаты на блокировку RPZ.
"""
import io

import pytest
from cryptography.fernet import Fernet

from config import Config  # noqa: E402

from app import create_app  # noqa: E402
from app.core.extensions import db  # noqa: E402
from app.core.models import User, UserService  # noqa: E402
from app.services.fstec.models import BlockEntry  # noqa: E402
from app.services.skydns.models import (
    SiemQueryLog,
    SkydnsCategory,
    ThreatDomain,
    ThreatHost,
)
from app.portal import SERVICES  # noqa: E402
from app.services.skydns.lib.siem_client import HostHit, SearchResult, SiemError  # noqa: E402
from app.services.skydns import routes as skydns_routes  # noqa: E402


class FakeSiemClient:
    """Заглушка SIEM: отдаёт заранее заданные хосты или падает."""

    instances = []

    def __init__(self, config):
        self.config = config
        self.closed = False
        self.searched = []
        self.batches = []
        FakeSiemClient.instances.append(self)

    login_error = None
    search_error = None
    hits = ()

    def login(self):
        if FakeSiemClient.login_error:
            raise SiemError(FakeSiemClient.login_error)

    def _result(self, domain, filter_template):
        return SearchResult(
            hosts=[HostHit(address=a, events_count=c) for a, c in FakeSiemClient.hits],
            total_count=sum(c for _, c in FakeSiemClient.hits),
            events_read=sum(c for _, c in FakeSiemClient.hits),
            query_filter=filter_template.replace("{domain}", domain),
        )

    def search_hosts(self, domain, time_from, time_to, filter_template, group_field):
        self.searched.append(domain)
        if FakeSiemClient.search_error:
            raise SiemError(FakeSiemClient.search_error)
        return self._result(domain, filter_template)

    def search_many(self, domains, time_from, time_to, filter_template,
                    group_field, limit=None):
        """Пачка доменов одним запросом — так работает боевой клиент."""
        self.searched.extend(domains)
        self.batches.append(list(domains))
        if FakeSiemClient.search_error:
            raise SiemError(FakeSiemClient.search_error)
        return {d: self._result(d, filter_template) for d in domains}

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
    from app.services.skydns.lib.skydns_client import Category, DomainStat

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
    from app.services.skydns.lib.skydns_client import Category, DeviceStat, DomainStat

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
    from app.services.skydns.lib.skydns_client import Category, DomainStat  # noqa: F401

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
    from app.services.skydns.lib.skydns_client import Category, DomainStat

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
    from app.services.skydns.lib.skydns_client import Category, DomainStat

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
    from app.core.models import BackgroundJob
    from app.services.skydns.lib.skydns_client import Category, DomainStat

    fake = _fake_skydns(
        monkeypatch,
        [Category(3, "Malware", True)],
        [DomainStat(f"evil{i}.ru", requests=i, cat_ids=[3]) for i in range(2000)],
    )
    _sync(client)

    assert fake.limit == 2000
    assert "Упёрлись в лимит" in BackgroundJob.query.one().message


def test_no_limit_warning_when_everything_fits(client, monkeypatch):
    from app.services.skydns.lib.skydns_client import Category, DomainStat

    _fake_skydns(monkeypatch, [Category(3, "Malware", True)],
                 [DomainStat("evil.ru", requests=1, cat_ids=[3])])
    assert "упёрлась в лимит" not in _sync(client).get_data(as_text=True)


def test_category_filter_matches_every_category_of_a_domain(client, monkeypatch):
    """Домен часто относится к нескольким категориям — искать надо по всем."""
    from app.services.skydns.lib.skydns_client import Category, DomainStat

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
    from app.services.skydns.lib.skydns_client import Category, DomainStat

    _fake_skydns(monkeypatch, [Category(3, "Malware", True)],
                 [DomainStat("evil.ru", requests=1, cat_ids=[3])])
    _sync(client)

    body = client.get("/skydns/domains").get_data(as_text=True)
    assert '<option value="3"' in body
    assert ">Malware</option>" in body


# --- поиск в SIEM идёт в фоне ---------------------------------------------

def test_lookup_returns_immediately_and_creates_a_job(client):
    """Страница не должна ждать SIEM: работа уходит в фоновое задание."""
    from app.core.models import BackgroundJob, JOB_KIND_SIEM

    threat_id = _add_threat()
    response = client.post(f"/skydns/domains/{threat_id}/lookup")
    assert response.status_code == 302

    job = BackgroundJob.query.one()
    assert job.kind == JOB_KIND_SIEM
    assert job.service_id == "skydns"
    assert job.total == 1
    assert "obltub.ru" in job.title


def test_job_summary_counts_domains_and_hosts(client):
    from app.core.models import BackgroundJob

    _add_threat("a-evil.ru")
    _add_threat("b-evil.ru")
    client.post("/skydns/lookup-batch")

    job = BackgroundJob.query.one()
    assert "Проверено доменов: 2" in job.message
    assert "Найдено хостов: 4" in job.message


def test_second_lookup_is_refused_while_the_first_runs(client):
    """Два поиска разом только поделят между собой и без того небыстрый SIEM."""
    from datetime import datetime

    from app.core.models import BackgroundJob, JOB_KIND_SIEM, JOB_RUNNING

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
    from app.core.models import BackgroundJob

    FakeSiemClient.hits = ()
    _add_threat()
    client.post("/skydns/lookup-batch")

    assert "Диагностика" in BackgroundJob.query.one().message


def test_login_failure_marks_the_job_as_failed(client):
    from app.core.models import BackgroundJob, JOB_FAILED

    FakeSiemClient.login_error = "SIEM отклонил вход (401)."
    _add_threat()
    client.post("/skydns/lookup-batch")

    job = BackgroundJob.query.one()
    assert job.status == JOB_FAILED
    assert "401" in job.message


# --- правила исключений ---------------------------------------------------

def _exclude(client, pattern, reason=""):
    return client.post("/skydns/exclusions", data={
        "pattern": pattern, "reason": reason, "submit_exclusion": "1",
    }, follow_redirects=True)


def test_rule_removes_already_loaded_domains(client):
    """Правило работает назад: разбирать уже загруженное заново незачем."""
    _add_threat("si21if1u2.afd.footprintdns.com")
    _add_threat("aa11.afd.footprintdns.com")
    _add_threat("evil.ru")

    _exclude(client, "*.footprintdns.com", "телеметрия")

    assert {t.domain for t in ThreatDomain.query.all()} == {"evil.ru"}
    from app.services.skydns.models import DomainExclusion
    assert DomainExclusion.query.one().removed_count == 2


def test_rule_respects_the_label_boundary(client):
    _add_threat("evilfootprintdns.com")
    _exclude(client, "*.footprintdns.com")
    assert ThreatDomain.query.filter_by(domain="evilfootprintdns.com").first()


def test_rule_keeps_new_domains_out_of_the_next_sync(client, monkeypatch):
    """И вперёд: иначе отсеянное возвращалось бы каждой выгрузкой."""
    from app.core.models import BackgroundJob
    from app.services.skydns.models import DomainExclusion
    from app.services.skydns.lib.skydns_client import Category, DomainStat

    _exclude(client, "*.footprintdns.com")
    _fake_skydns(
        monkeypatch,
        [Category(3, "Malware", True)],
        [DomainStat("x1.afd.footprintdns.com", requests=5, cat_ids=[3]),
         DomainStat("evil.ru", requests=7, cat_ids=[3])],
    )
    _sync(client)

    assert {t.domain for t in ThreatDomain.query.all()} == {"evil.ru"}
    assert "Отсеяно правилами исключений: 1" in BackgroundJob.query.one().message
    # Счётчик срабатываний отвечает на вопрос «правило ещё нужно?».
    assert DomainExclusion.query.one().hits_count == 1


def test_duplicate_rule_is_not_created_twice(client):
    _exclude(client, "*.example.com")
    _exclude(client, "*.Example.com.")
    from app.services.skydns.models import DomainExclusion
    assert DomainExclusion.query.count() == 1


def test_removing_a_rule_lets_domains_come_back(client, monkeypatch):
    from app.services.skydns.models import DomainExclusion
    from app.services.skydns.lib.skydns_client import Category, DomainStat

    _exclude(client, "*.footprintdns.com")
    rule_id = DomainExclusion.query.one().id
    client.post(f"/skydns/exclusions/{rule_id}/delete", follow_redirects=True)

    _fake_skydns(
        monkeypatch,
        [Category(3, "Malware", True)],
        [DomainStat("x1.afd.footprintdns.com", requests=5, cat_ids=[3])],
    )
    _sync(client)
    assert ThreatDomain.query.filter_by(
        domain="x1.afd.footprintdns.com").first()


def test_exclude_from_the_threat_card_covers_the_whole_service(client):
    """Самый частый путь: увидел очередной поддомен — убрал сервис целиком."""
    kept = _add_threat("evil.ru")
    threat_id = _add_threat("si21if1u2.afd.footprintdns.com")
    _add_threat("bb22.afd.footprintdns.com")

    client.post(f"/skydns/domains/{threat_id}/exclude", data={"scope": "root"},
                follow_redirects=True)

    from app.services.skydns.models import DomainExclusion
    assert DomainExclusion.query.one().pattern == "*.footprintdns.com"
    assert [t.id for t in ThreatDomain.query.all()] == [kept]


# --- свёртка до корневых --------------------------------------------------

def test_root_domain_is_filled_on_insert(client, monkeypatch):
    from app.services.skydns.lib.skydns_client import Category, DomainStat

    _fake_skydns(
        monkeypatch,
        [Category(3, "Malware", True)],
        [DomainStat("si21if1u2.afd.footprintdns.com", requests=5, cat_ids=[3])],
    )
    _sync(client)
    threat = ThreatDomain.query.one()
    assert threat.root_domain == "footprintdns.com"
    assert threat.subdomain == "si21if1u2.afd"


def test_roots_page_groups_names_of_one_service(client):
    _add_threat("a.footprintdns.com")
    _add_threat("b.footprintdns.com")
    _add_threat("evil.ru")
    for threat in ThreatDomain.query.all():
        from app.services.skydns.lib.domains import registrable
        threat.root_domain = registrable(threat.domain)
    db.session.commit()

    body = client.get("/skydns/roots").get_data(as_text=True)
    assert "footprintdns.com" in body
    # Отдельных строк на каждое имя быть не должно — в этом весь смысл.
    assert "a.footprintdns.com" not in body


def test_domains_can_be_filtered_by_root(client):
    from app.services.skydns.lib.domains import registrable

    _add_threat("a.footprintdns.com")
    _add_threat("evil.ru")
    for threat in ThreatDomain.query.all():
        threat.root_domain = registrable(threat.domain)
    db.session.commit()

    body = client.get("/skydns/domains?root=footprintdns.com").get_data(as_text=True)
    assert "a.footprintdns.com" in body
    assert "evil.ru" not in body


# --- хосты по категориям --------------------------------------------------

def test_category_page_shows_who_went_where(client):
    from app.services.skydns.models import SkydnsCategory

    db.session.add(SkydnsCategory(id=4, title="Phishing", is_dangerous=True))
    threat = ThreatDomain(domain="phish.ru", cat_ids="4", root_domain="phish.ru")
    db.session.add(threat)
    db.session.flush()
    db.session.add(ThreatHost(threat_id=threat.id, address="10.61.50.40",
                              events_count=12, source="siem"))
    db.session.commit()

    body = client.get("/skydns/by-category").get_data(as_text=True)
    assert "Phishing" in body

    body = client.get("/skydns/by-category/4").get_data(as_text=True)
    assert "10.61.50.40" in body and "phish.ru" in body


def test_category_match_does_not_bleed_between_ids(client):
    """cat_ids хранится строкой: поиск «1» не должен ловить 12 и 71."""
    from app.services.skydns.models import SkydnsCategory

    db.session.add(SkydnsCategory(id=1, title="Новые домены", is_dangerous=True))
    threat = ThreatDomain(domain="bot.ru", cat_ids="12,71", root_domain="bot.ru")
    db.session.add(threat)
    db.session.flush()
    db.session.add(ThreatHost(threat_id=threat.id, address="10.0.0.9",
                              events_count=1, source="siem"))
    db.session.commit()

    body = client.get("/skydns/by-category/1").get_data(as_text=True)
    assert "10.0.0.9" not in body


# --- пакетное удаление ----------------------------------------------------

def test_batch_delete_removes_selected_domains(client):
    keep = _add_threat("keep.ru")
    drop = _add_threat("drop.ru")
    client.post("/skydns/domains/delete-batch",
                data={"threat_id": [str(drop)]}, follow_redirects=True)
    assert [t.id for t in ThreatDomain.query.all()] == [keep]


# --- проверка в VirusTotal ------------------------------------------------

def _fake_vt(monkeypatch, malicious=7, rate_limit_after=None):
    """Подставной VirusTotal: считает вызовы, умеет упереться в лимит."""
    from app.core import vt_client, vt_store

    calls = []

    def fake_check(value, api_key, timeout=20):
        calls.append(value)
        if rate_limit_after is not None and len(calls) > rate_limit_after:
            raise vt_client.VtRateLimit("Превышен лимит запросов.")
        return vt_client.VtResult(
            value=value, kind="domain", malicious=malicious,
            harmless=60, permalink=f"https://vt/{value}",
        )

    monkeypatch.setattr(vt_store.vt_client, "check", fake_check)
    return calls


def test_vt_check_from_the_threat_card(client, monkeypatch):
    from app.core.models import VtReport

    calls = _fake_vt(monkeypatch)
    threat_id = _add_threat("evil.ru")
    client.post(f"/skydns/domains/{threat_id}/vt", follow_redirects=True)

    assert calls == ["evil.ru"]
    report = VtReport.query.filter_by(value="evil.ru").one()
    assert report.malicious == 7
    assert report.total_engines == 67


def test_vt_batch_checks_selected_domains(client, monkeypatch):
    calls = _fake_vt(monkeypatch)
    ids = [_add_threat("a.ru"), _add_threat("b.ru")]
    client.post("/skydns/vt-batch",
                data={"threat_id": [str(i) for i in ids]},
                follow_redirects=True)
    assert sorted(calls) == ["a.ru", "b.ru"]


def test_vt_batch_stops_on_the_rate_limit(client, monkeypatch):
    """Упёршись в лимит, продолжать бессмысленно — запросы уйдут в отказы."""
    calls = _fake_vt(monkeypatch, rate_limit_after=1)
    ids = [_add_threat(f"d{i}.ru") for i in range(4)]
    response = client.post("/skydns/vt-batch",
                           data={"threat_id": [str(i) for i in ids]},
                           follow_redirects=True)
    assert len(calls) == 2, "после отказа по лимиту запросы должны прекратиться"
    assert "Проверка остановлена" in response.get_data(as_text=True)


def test_vt_failure_is_recorded_not_lost(client, monkeypatch):
    from app.core.models import VtReport
    from app.core import vt_client, vt_store

    def boom(value, api_key, timeout=20):
        raise vt_client.VtError("Ключ VirusTotal не задан.")

    monkeypatch.setattr(vt_store.vt_client, "check", boom)
    threat_id = _add_threat("evil.ru")
    client.post(f"/skydns/domains/{threat_id}/vt", follow_redirects=True)

    assert "не задан" in VtReport.query.filter_by(value="evil.ru").one().error


# --- пачки доменов в SIEM -------------------------------------------------

def test_domains_go_to_siem_in_batches(client):
    """Не по одному запросу на домен: на длинном списке это часы."""
    from app.services.skydns.settings import KEY_SIEM_CHUNK, set_setting

    set_setting(KEY_SIEM_CHUNK, "3")
    db.session.commit()
    for i in range(7):
        _add_threat(f"evil{i}.ru")

    client.post("/skydns/lookup-batch")

    batches = FakeSiemClient.instances[0].batches
    assert [len(b) for b in batches] == [3, 3, 1]
    assert len({d for b in batches for d in b}) == 7


def test_chunk_of_one_keeps_the_old_behaviour(client):
    from app.services.skydns.settings import KEY_SIEM_CHUNK, set_setting

    set_setting(KEY_SIEM_CHUNK, "1")
    db.session.commit()
    _add_threat("a.ru")
    _add_threat("b.ru")

    client.post("/skydns/lookup-batch")
    assert [len(b) for b in FakeSiemClient.instances[0].batches] == [1, 1]


def test_every_domain_of_a_batch_gets_its_own_log(client):
    """Журнал ведётся по доменам, хотя запрос был общий."""
    _add_threat("a.ru")
    _add_threat("b.ru")
    client.post("/skydns/lookup-batch")

    logs = {log.domain: log for log in SiemQueryLog.query.all()}
    assert set(logs) == {"a.ru", "b.ru"}
    assert all(log.status == "success" for log in logs.values())


def test_batch_failure_is_recorded_for_every_domain_in_it(client):
    """Запрос был общий — значит, и ошибка общая для всей пачки."""
    FakeSiemClient.search_error = "SIEM вернул ошибку 500."
    _add_threat("a.ru")
    _add_threat("b.ru")
    client.post("/skydns/lookup-batch")

    logs = SiemQueryLog.query.all()
    assert len(logs) == 2
    assert all(log.status == "failed" for log in logs)
    assert all(t.siem_checked_at is None for t in ThreatDomain.query.all())


def test_no_cap_on_the_number_of_domains(client):
    """Прежний предел в 200 доменов за раз снят."""
    for i in range(250):
        _add_threat(f"evil{i}.ru")
    client.post("/skydns/lookup-batch")

    assert ThreatDomain.query.filter(
        ThreatDomain.siem_checked_at.is_(None)
    ).count() == 0


# --- шаблон фильтра SIEM --------------------------------------------------

def test_legacy_filter_is_replaced_by_the_current_one(client):
    """Старое умолчание не находило поддомены — оператор его не выбирал."""
    from app.services.skydns.settings import (
        DEFAULT_SIEM_FILTER,
        KEY_SIEM_FILTER,
        LEGACY_SIEM_FILTERS,
        get_siem_filter_template,
        set_setting,
    )

    set_setting(KEY_SIEM_FILTER, LEGACY_SIEM_FILTERS[0])
    db.session.commit()
    assert get_siem_filter_template() == DEFAULT_SIEM_FILTER


def test_own_filter_is_left_alone(client):
    """Свой шаблон оператора трогать нельзя."""
    from app.services.skydns.settings import (
        KEY_SIEM_FILTER,
        get_siem_filter_template,
        set_setting,
    )

    mine = 'datafield6 = "{domain}" and event_src.category = "DNS server"'
    set_setting(KEY_SIEM_FILTER, mine)
    db.session.commit()
    assert get_siem_filter_template() == mine


def test_settings_page_shows_the_effective_filter(client):
    """В форме должен стоять тот шаблон, который реально уходит в SIEM."""
    from app.services.skydns.settings import KEY_SIEM_FILTER, LEGACY_SIEM_FILTERS, set_setting

    set_setting(KEY_SIEM_FILTER, LEGACY_SIEM_FILTERS[0])
    db.session.commit()
    body = client.get("/skydns/settings").get_data(as_text=True)
    assert "datafield6" in body


# --- отказ пачки не должен уносить здоровые домены ------------------------

def test_failed_batch_is_retried_domain_by_domain(client, monkeypatch):
    """Отказ по пачке ничего не говорит о конкретном домене."""
    from app.core.models import BackgroundJob

    original = FakeSiemClient.search_many

    def flaky(self, domains, *args, **kwargs):
        # Пачкой не отвечаем (как будто фильтр слишком длинный),
        # поштучно — отвечаем.
        if len(domains) > 1:
            raise SiemError("SIEM вернул ошибку 400 на запрос событий.")
        return original(self, domains, *args, **kwargs)

    monkeypatch.setattr(FakeSiemClient, "search_many", flaky)
    for i in range(3):
        _add_threat(f"evil{i}.ru")

    client.post("/skydns/lookup-batch")

    # Все домены проверены, несмотря на отказ пачки.
    assert ThreatDomain.query.filter(
        ThreatDomain.siem_checked_at.is_(None)
    ).count() == 0
    assert "Проверено доменов: 3" in BackgroundJob.query.one().message


def test_single_domain_failure_is_reported_for_that_domain(client, monkeypatch):
    """Если не отвечает и поштучно — ошибка ложится на свой домен."""
    def always_fails(self, domains, *args, **kwargs):
        # Домен ломает и общий запрос, и свой собственный.
        if "bad.ru" in domains:
            raise SiemError("SIEM вернул ошибку 500.")
        return {d: SearchResult(query_filter="x") for d in domains}

    monkeypatch.setattr(FakeSiemClient, "search_many", always_fails)
    _add_threat("good.ru")
    _add_threat("bad.ru")
    client.post("/skydns/lookup-batch")

    logs = {log.domain: log for log in SiemQueryLog.query.all()}
    assert logs["bad.ru"].status == "failed"
    assert logs["good.ru"].status == "success"
    # Здоровый домен отмечен проверенным, сбойный — нет.
    threats = {t.domain: t for t in ThreatDomain.query.all()}
    assert threats["good.ru"].siem_checked_at is not None
    assert threats["bad.ru"].siem_checked_at is None


# --- снятие зависшего задания ---------------------------------------------

def test_cancelled_job_frees_the_next_run(client):
    """После перезапуска службы запись остаётся «выполняется»."""
    from datetime import datetime

    from app.core.models import BackgroundJob, JOB_KIND_SIEM, JOB_RUNNING

    stuck = BackgroundJob(
        kind=JOB_KIND_SIEM, status=JOB_RUNNING, title="осталось от перезапуска",
        heartbeat_at=datetime.utcnow(), user_id=User.query.one().id,
    )
    db.session.add(stuck)
    db.session.commit()

    # Пока задание висит, новый поиск не запускается.
    threat_id = _add_threat()
    client.post(f"/skydns/domains/{threat_id}/lookup")
    assert BackgroundJob.query.count() == 1

    assert client.post(f"/jobs/{stuck.id}/cancel").get_json()["ok"] is True
    assert db.session.get(BackgroundJob, stuck.id).status == "failed"

    # А теперь — запускается.
    client.post(f"/skydns/domains/{threat_id}/lookup")
    assert BackgroundJob.query.count() == 2


def test_worker_stops_when_the_job_is_cancelled(app):
    """Снятое задание не должно дописывать результаты задним числом."""
    from app.core.models import BackgroundJob, JOB_KIND_SIEM
    from app.core import background as jobs

    steps = []

    def work(handle):
        handle.progress(processed=1, detail="первый")
        steps.append(1)
        jobs.cancel(db.session.get(BackgroundJob, handle.job_id))
        handle.progress(processed=2, detail="второй")   # здесь и остановится
        steps.append(2)
        return "не должно попасть в итог"

    job = jobs.start(app, kind=JOB_KIND_SIEM, title="Тест", worker=work,
                     total=2, user_id=User.query.one().id)
    assert steps == [1]
    assert job.status == "failed"
    assert "Снято оператором" in job.message
