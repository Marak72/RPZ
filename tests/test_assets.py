"""Тесты сервиса «Узлы сети».

Внешние системы (Active Directory и DHCP) заменены заглушками: проверяется
разбор ответов, слияние в базу, ведение истории и страницы сервиса.
"""
from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from config import Config  # noqa: E402

from app import create_app  # noqa: E402
from app.core.extensions import db  # noqa: E402
from app.core.models import User, UserService  # noqa: E402
from app.portal import SERVICES  # noqa: E402
from app.services.assets import routes as assets_routes  # noqa: E402
from app.services.assets.lib import classify, inventory  # noqa: E402
from app.services.assets.lib.dhcp_client import (  # noqa: E402
    DhcpError,
    DhcpLease,
    DhcpScopeInfo,
    _guard,
    _parse_ps_datetime,
    _rows,
    leases_from_rows,
    scopes_from_rows,
    servers_from_rows,
)
from app.services.assets.lib.ipaddr import (  # noqa: E402
    in_range,
    ip_to_int,
    is_hostname,
    normalize_mac,
    parse_ip,
    short_name,
)
from app.services.assets.lib.ldap_client import (  # noqa: E402
    AdComputer as AdComputerDTO,
)
from app.services.assets.lib.ldap_client import (  # noqa: E402
    base_dn_from_domain,
    computer_from_entry,
    escape_filter,
    ou_from_dn,
)
from app.services.assets.models import (  # noqa: E402
    AdComputer,
    AssetLookup,
    HostObservation,
    NetworkHost,
)


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    RPZ_FERNET_KEY = Fernet.generate_key().decode()


@pytest.fixture
def app():
    application = create_app(TestConfig)
    with application.app_context():
        db.create_all()
        user = User(username="op", role="operator", full_name="Оператор")
        user.set_password("pass")
        db.session.add(user)
        db.session.flush()
        for service in SERVICES:
            db.session.add(UserService(user_id=user.id, service_id=service.id))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    test_client = app.test_client()
    test_client.post("/login", data={"username": "op", "password": "pass"})
    return test_client


def _lease(ip="10.10.24.50", hostname="PC-IVANOV", mac="00-1A-2B-3C-4D-5E",
           state="Active", expires=None, scope="10.10.24.0", server="dhcp1"):
    return DhcpLease(ip=ip, hostname=hostname, mac=mac, state=state,
                     expires_at=expires, scope_id=scope, server=server)


def _computer(name="pc-ivanov", os_name="Windows 10 Pro",
              dn="CN=PC-IVANOV,OU=Компьютеры,OU=Отдел кадров,DC=adm72,DC=local"):
    return AdComputerDTO(name=name, fqdn=name + ".adm72.local", dn=dn,
                         description="Иванов И.И., каб. 305", os=os_name,
                         os_version="10.0", enabled=True,
                         last_logon=datetime(2026, 8, 1, 9, 0))


# --- разбор адресов --------------------------------------------------------

def test_ip_parsing_rejects_junk():
    assert parse_ip("10.10.24.11") == "10.10.24.11"
    assert parse_ip(" 10.10.24.11 ") == "10.10.24.11"
    # Лишние нули и маска — не адрес: в базе должен быть один вид записи.
    assert parse_ip("10.10.24.011") == ""
    assert parse_ip("10.10.24.11/26") == ""
    assert parse_ip("не адрес") == ""


def test_ip_sorting_is_numeric_not_alphabetic():
    """Строкой «10.10.9.1» больше «10.10.10.1» — список выглядел бы случайным."""
    assert ip_to_int("10.10.9.1") < ip_to_int("10.10.10.1")


def test_range_check_is_inclusive():
    assert in_range("10.10.24.1", "10.10.24.1", "10.10.24.254")
    assert in_range("10.10.24.254", "10.10.24.1", "10.10.24.254")
    assert not in_range("10.10.25.1", "10.10.24.1", "10.10.24.254")


def test_mac_normalized_from_any_form():
    assert normalize_mac("00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("001a2b3c4d5e") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("00:1a:2b:3c:4d") == ""


def test_short_name_strips_domain():
    assert short_name("PC-IVANOV.adm72.local") == "pc-ivanov"
    assert short_name("") == ""


def test_hostname_is_not_confused_with_address():
    assert is_hostname("pc-ivanov")
    assert not is_hostname("10.10.24.11")
    assert not is_hostname("00:1a:2b:3c:4d:5e")


# --- разбор ответов AD -----------------------------------------------------

def test_ou_path_is_readable_and_drops_the_object_itself():
    dn = "CN=PC-01,OU=Компьютеры,OU=Отдел кадров,OU=Тюмень,DC=adm72,DC=local"
    assert ou_from_dn(dn) == "Тюмень / Отдел кадров / Компьютеры"


def test_base_dn_built_from_domain():
    assert base_dn_from_domain("adm72.local") == "DC=adm72,DC=local"


def test_ldap_filter_escapes_special_characters():
    """Без экранирования звёздочка в имени меняла бы смысл запроса."""
    assert escape_filter("pc*") == "pc\\2a"
    assert escape_filter("a(b)") == "a\\28b\\29"


def test_disabled_computer_recognized_by_uac_bit():
    entry = {"cn": ["PC-OLD"], "userAccountControl": ["4098"]}
    assert computer_from_entry(entry).enabled is False
    entry_ok = {"cn": ["PC-NEW"], "userAccountControl": ["4096"]}
    assert computer_from_entry(entry_ok).enabled is True


def test_last_logon_converted_from_windows_filetime():
    # 133000000000000000 — начало 2022 года в FILETIME.
    entry = {"cn": ["PC"], "lastLogonTimestamp": ["133000000000000000"]}
    value = computer_from_entry(entry).last_logon
    assert value is not None and value.year == 2022


# --- разбор ответов DHCP ---------------------------------------------------

def test_lease_parsed_from_powershell_json():
    raw = ('[{"IPAddress":"10.10.24.50","ScopeId":"10.10.24.0",'
           '"ClientId":"00-1a-2b-3c-4d-5e","HostName":"pc-ivanov.adm72.local",'
           '"AddressState":"Active","LeaseExpiryTime":"2026-08-20T10:00:00"}]')
    leases = leases_from_rows(_rows(raw), server="dhcp1")
    assert len(leases) == 1
    assert leases[0].ip == "10.10.24.50"
    assert leases[0].mac == "00:1a:2b:3c:4d:5e"
    assert leases[0].expires_at == datetime(2026, 8, 20, 10, 0)


def test_empty_powershell_output_is_not_an_error():
    """Команда без объектов печатает пустую строку — это «ничего не нашлось»."""
    assert _rows("") == []
    assert _rows("   \n") == []


def test_single_object_answer_is_accepted():
    """На всякий случай: если ответ приедет объектом, а не списком."""
    rows = _rows('{"IPAddress":"10.0.0.1"}')
    assert len(rows) == 1


def test_unparseable_answer_explains_itself():
    with pytest.raises(DhcpError) as exc:
        _rows("Get-DhcpServerv4Lease : Отказано в доступе")
    assert "неразборчивый" in str(exc.value)


def test_legacy_date_format_still_understood():
    assert _parse_ps_datetime("/Date(1755164700000)/") is not None


def test_reservation_recognized():
    lease = _lease(state="ActiveReservation")
    assert lease.is_reservation


def test_scopes_and_servers_parsed():
    scopes = scopes_from_rows([{
        "ScopeId": "10.10.24.0", "SubnetMask": "255.255.255.0",
        "Name": "Тюмень, ул. Сакко", "State": "Active",
        "StartRange": "10.10.24.10", "EndRange": "10.10.24.200",
    }])
    assert scopes[0].name == "Тюмень, ул. Сакко"
    servers = servers_from_rows([{"DnsName": "dhcp1.adm72.local",
                                  "IPAddress": "10.61.7.17"}])
    assert servers[0].name == "dhcp1.adm72.local"


def test_only_read_commands_reach_the_server():
    """Защита от записи: до DHCP-сервера уходят только Get-*."""
    with pytest.raises(DhcpError) as exc:
        _guard("Remove-DhcpServerv4Lease -IPAddress 10.0.0.1")
    assert "не являющуюся чтением" in str(exc.value)
    # А обычный запрос чтения проходит.
    _guard("$ErrorActionPreference='Stop'\nGet-DhcpServerv4Lease -ScopeId '1.1.1.0'")


def test_server_name_with_quotes_is_rejected():
    """Имя сервера подставляется в кавычки PowerShell — мусор туда не пустим."""
    from app.services.assets.lib.dhcp_client import _safe_host

    with pytest.raises(DhcpError):
        _safe_host("dhcp1'; Remove-Item C:\\ -Recurse; '")


# --- определение вида узла -------------------------------------------------

def test_server_os_beats_name():
    assert classify.classify(name="pc-01", os_name="Windows Server 2019") \
        == classify.KIND_SERVER


def test_domain_controller_recognized_by_placement():
    kind = classify.classify(name="whatever",
                             dn="CN=DC1,OU=Domain Controllers,DC=adm72,DC=local")
    assert kind == classify.KIND_DC


def test_network_gear_recognized_by_name():
    assert classify.classify(name="ns1-perv") == classify.KIND_NETWORK
    assert classify.classify(name="gw-malig") == classify.KIND_NETWORK


def test_infrastructure_nodes_are_marked_as_such():
    """За шлюзом и DNS сотрудника нет — сервис обязан сказать об этом прямо."""
    assert classify.is_infrastructure(classify.KIND_NETWORK)
    assert not classify.is_infrastructure(classify.KIND_WORKSTATION)


# --- слияние в базу --------------------------------------------------------

def test_lease_creates_host_and_first_observation(app):
    host, created = inventory.upsert_lease(_lease())
    db.session.commit()
    assert created
    assert host.ip == "10.10.24.50"
    assert host.hostname == "pc-ivanov"
    assert host.mac == "00:1a:2b:3c:4d:5e"
    assert HostObservation.query.count() == 1


def test_repeated_lease_does_not_grow_the_history(app):
    """Выгрузка идёт по расписанию: без этого история распухла бы от повторов."""
    inventory.upsert_lease(_lease())
    db.session.commit()
    for _ in range(5):
        inventory.upsert_lease(_lease())
        db.session.commit()
    assert NetworkHost.query.count() == 1
    assert HostObservation.query.count() == 1


def test_new_machine_on_the_same_address_is_recorded(app):
    """Ради этого история и ведётся: вчера адрес был другой машины."""
    inventory.upsert_lease(_lease())
    db.session.commit()
    inventory.upsert_lease(_lease(hostname="PC-PETROV",
                                  mac="aa-bb-cc-dd-ee-ff"))
    db.session.commit()

    host = NetworkHost.query.filter_by(ip="10.10.24.50").first()
    assert host.hostname == "pc-petrov"
    changes = [o.change for o in HostObservation.query.all()]
    assert any("pc-ivanov → pc-petrov" in c for c in changes)


def test_stale_ad_link_is_dropped_when_the_machine_changes(app):
    """Иначе карточка показывала бы описание прежнего владельца адреса."""
    inventory.upsert_lease(_lease())
    inventory.upsert_computer(_computer())
    db.session.commit()
    inventory.link_all()
    db.session.commit()
    assert NetworkHost.query.first().ad_computer is not None

    inventory.upsert_lease(_lease(hostname="PC-PETROV"))
    db.session.commit()

    host = NetworkHost.query.first()
    assert host.ad_computer is None, "связь со старым объектом AD не оборвана"
    assert host.display_name == "pc-petrov"


def test_display_name_prefers_the_lease_over_the_catalogue(app):
    """Аренда свежее: зеркало AD обновляется реже, чем меняется адрес."""
    inventory.upsert_lease(_lease())
    inventory.upsert_computer(_computer())
    db.session.commit()
    inventory.link_all()
    db.session.commit()
    host = NetworkHost.query.first()
    host.hostname = "pc-later"
    assert host.display_name == "pc-later"


def test_host_links_to_ad_computer_by_name(app):
    inventory.upsert_lease(_lease())
    inventory.upsert_computer(_computer())
    db.session.commit()

    linked = inventory.link_all()
    db.session.commit()
    assert linked == 1

    host = NetworkHost.query.first()
    assert host.ad_computer is not None
    assert host.ad_computer.ou_path == "Отдел кадров / Компьютеры"
    # Вид узла пересчитан по данным AD, а не по имени.
    assert host.kind == classify.KIND_WORKSTATION


def test_ad_data_wins_over_name_when_classifying(app):
    """Имя «s-buh» намекает на сервер, но в AD это станция с Windows 10."""
    inventory.upsert_lease(_lease(hostname="s-buh"))
    inventory.upsert_computer(_computer(name="s-buh", os_name="Windows 10 Pro"))
    db.session.commit()
    inventory.link_all()
    db.session.commit()
    assert NetworkHost.query.first().kind == classify.KIND_WORKSTATION


def test_scope_map_routes_address_to_its_server(app):
    inventory.upsert_scope("dhcp1", DhcpScopeInfo(
        scope_id="10.10.24.0", name="Сакко", mask="255.255.255.0",
        start="10.10.24.10", end="10.10.24.200", state="Active"))
    db.session.commit()

    assert inventory.server_for_ip("10.10.24.50") == "dhcp1"
    # Адрес вне области — статический, опрашивать площадки незачем.
    assert inventory.server_for_ip("10.99.0.1") == ""


def test_lease_without_address_is_rejected(app):
    with pytest.raises(ValueError):
        inventory.upsert_lease(_lease(ip="не адрес"))


# --- страницы --------------------------------------------------------------

def test_service_pages_open(client):
    for url in ("/assets/", "/assets/search", "/assets/hosts",
                "/assets/computers", "/assets/scopes", "/assets/logs",
                "/assets/sync", "/assets/settings"):
        response = client.get(url)
        assert response.status_code == 200, url


def test_search_by_ip_finds_the_host(app, client):
    with app.app_context():
        inventory.upsert_lease(_lease())
        inventory.upsert_computer(_computer())
        db.session.commit()
        inventory.link_all()
        db.session.commit()

    response = client.get("/assets/search?q=10.10.24.50")
    body = response.get_data(as_text=True)
    assert "pc-ivanov" in body
    assert "Отдел кадров" in body


def test_search_by_partial_name_finds_both_halves(app, client):
    with app.app_context():
        inventory.upsert_lease(_lease())
        inventory.upsert_computer(_computer())
        db.session.commit()
        inventory.link_all()
        db.session.commit()

    body = client.get("/assets/search?q=ivanov").get_data(as_text=True)
    assert "10.10.24.50" in body


def test_search_ignores_case_in_russian_text(app, client):
    """Встроенный lower() в SQLite кириллицу не приводит — поиск бы промахнулся."""
    with app.app_context():
        inventory.upsert_lease(_lease())
        inventory.upsert_computer(_computer())
        db.session.commit()
        inventory.link_all()
        db.session.commit()

    # В описании — «Иванов И.И.», ищем строчными.
    body = client.get("/assets/search?q=иванов").get_data(as_text=True)
    assert "pc-ivanov" in body
    # И наоборот: в базе строчное «Отдел кадров», ищем прописными.
    body = client.get("/assets/computers?q=ОТДЕЛ КАДРОВ").get_data(as_text=True)
    assert "pc-ivanov" in body


def test_search_is_written_to_the_journal(app, client):
    client.get("/assets/search?q=10.10.24.50")
    with app.app_context():
        row = AssetLookup.query.first()
        assert row is not None
        assert row.term == "10.10.24.50"
        assert row.query_kind == "ip"
        assert row.found is False


def test_unknown_address_offers_a_live_check(client):
    body = client.get("/assets/search?q=10.99.99.99").get_data(as_text=True)
    assert "Ничего не найдено" in body
    assert "/assets/host/10.99.99.99" in body


def test_host_card_shows_everything_known(app, client):
    with app.app_context():
        inventory.upsert_lease(_lease())
        inventory.upsert_computer(_computer())
        db.session.commit()
        inventory.link_all()
        db.session.commit()

    body = client.get("/assets/host/10.10.24.50").get_data(as_text=True)
    assert "00:1a:2b:3c:4d:5e" in body
    assert "Иванов И.И." in body
    assert "Рабочая станция" in body


def test_card_of_infrastructure_node_warns_about_it(app, client):
    """Главное предупреждение сервиса: за этим адресом человека нет."""
    with app.app_context():
        inventory.upsert_lease(_lease(ip="10.170.253.5", hostname="ns1-perv"))
        db.session.commit()

    body = client.get("/assets/host/10.170.253.5").get_data(as_text=True)
    assert "не рабочее место" in body


def test_expired_lease_is_flagged(app, client):
    with app.app_context():
        inventory.upsert_lease(_lease(
            expires=datetime.utcnow() - timedelta(days=2)))
        db.session.commit()

    body = client.get("/assets/host/10.10.24.50").get_data(as_text=True)
    assert "Срок аренды истёк" in body


def test_missing_address_explains_why(client):
    body = client.get("/assets/host/10.99.99.99").get_data(as_text=True)
    assert "назначен статически" in body


def test_bad_address_does_not_crash(client):
    response = client.get("/assets/host/не-адрес", follow_redirects=True)
    assert response.status_code == 200


def test_manual_host_can_be_added(app, client):
    response = client.post("/assets/hosts/add", data={
        "ip": "10.10.24.11", "hostname": "socelkserver",
        "notes": "Портал SOC", "submit_manual": "1",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        host = NetworkHost.query.filter_by(ip="10.10.24.11").first()
        assert host is not None
        assert host.notes == "Портал SOC"


def test_csv_export_has_the_columns(app, client):
    with app.app_context():
        inventory.upsert_lease(_lease())
        db.session.commit()
    response = client.get("/assets/hosts.csv")
    body = response.get_data(as_text=True)
    assert "Адрес;Имя;MAC" in body
    assert "10.10.24.50" in body


def test_live_check_uses_dhcp_and_ad(app, client, monkeypatch):
    """Кнопка «Проверить сейчас»: спрашиваем внешние системы, а не базу."""

    class FakeDhcp:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def find_lease(self, server, ip):
            return _lease(ip=ip)

    class FakeLdap:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def find_computer(self, name):
            return _computer(name=name)

    monkeypatch.setattr(assets_routes, "DhcpClient", FakeDhcp)
    monkeypatch.setattr(assets_routes, "LdapClient", FakeLdap)
    monkeypatch.setattr(assets_routes, "load_dhcp_config",
                        lambda: _FakeConfig())
    monkeypatch.setattr(assets_routes, "load_ldap_config",
                        lambda: _FakeConfig())

    response = client.post("/assets/host/10.10.24.50/refresh",
                           follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        host = NetworkHost.query.filter_by(ip="10.10.24.50").first()
        assert host is not None
        assert host.checked_at is not None
        assert host.ad_computer is not None
        # Живая проверка тоже попадает в журнал.
        assert AssetLookup.query.filter_by(is_live=True).count() == 1


def test_live_check_reports_failure_instead_of_crashing(app, client, monkeypatch):
    class FailingDhcp:
        def __init__(self, config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def find_lease(self, server, ip):
            raise DhcpError("Отказано в доступе")

    monkeypatch.setattr(assets_routes, "DhcpClient", FailingDhcp)
    monkeypatch.setattr(assets_routes, "load_dhcp_config", lambda: _FakeConfig())

    response = client.post("/assets/host/10.10.24.50/refresh",
                           follow_redirects=True)
    assert "Отказано в доступе" in response.get_data(as_text=True)
    with app.app_context():
        assert AssetLookup.query.filter(AssetLookup.error != "").count() == 1


class _FakeConfig:
    host = "dc"
    is_configured = True


def test_skydns_host_page_links_to_the_asset_card(app, client):
    """Ссылка между сервисами: из карточки хоста SkyDNS в «Узлы сети»."""
    from app.services.skydns.models import ThreatDomain, ThreatHost

    with app.app_context():
        threat = ThreatDomain(domain="evil.ru", category="malware")
        db.session.add(threat)
        db.session.flush()
        db.session.add(ThreatHost(threat_id=threat.id, address="10.10.24.50"))
        db.session.commit()

    body = client.get("/skydns/host?address=10.10.24.50").get_data(as_text=True)
    assert "/assets/host/10.10.24.50" in body


def test_service_is_closed_without_a_grant(app):
    """Сервис виден только тем, кому его выдал администратор."""
    with app.app_context():
        user = User(username="nobody", role="operator")
        user.set_password("pass")
        db.session.add(user)
        db.session.commit()

    other = app.test_client()
    other.post("/login", data={"username": "nobody", "password": "pass"})
    assert other.get("/assets/").status_code == 403
