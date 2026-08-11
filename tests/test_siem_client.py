"""Тесты клиента MaxPatrol SIEM: сборка запроса и разбор ответа.

Сеть не задействуется — проверяются только чистые функции.
"""
import json
from datetime import datetime

import pytest

from app.services import siem_client
from app.services.siem_client import SiemError

TIME_FROM = datetime(2026, 8, 1, 0, 0, 0)
TIME_TO = datetime(2026, 8, 7, 0, 0, 0)


# --- адреса компонентов ---------------------------------------------------

def test_core_url_adds_port_3334():
    url = siem_client._core_url("https://siem.local", "/connect/token")
    assert url == "https://siem.local:3334/connect/token"


def test_core_url_keeps_explicit_port():
    """Если порт задали руками, подменять его нельзя."""
    url = siem_client._core_url("https://siem.local:8443", "/ui/login")
    assert url == "https://siem.local:8443/ui/login"


def test_core_url_ignores_default_ports():
    """Адрес, скопированный из адресной строки, мог принести :443.

    Это не «осознанно выбранный порт», а порт схемы по умолчанию: вход в
    Core всё равно живёт на 3334, иначе аутентификация уходила бы в никуда.
    """
    assert siem_client._core_url("https://siem.local:443", "/ui/login") == \
        "https://siem.local:3334/ui/login"
    assert siem_client._core_url("http://siem.local:80", "/ui/login") == \
        "http://siem.local:3334/ui/login"


def test_base_url_without_scheme_becomes_https():
    assert siem_client._api_url("siem.local", "/api/x") == "https://siem.local/api/x"


def test_empty_base_url_is_rejected():
    with pytest.raises(SiemError):
        siem_client._api_url("", "/api/x")


# --- фильтр ---------------------------------------------------------------

def test_filter_template_substitutes_domain():
    result = siem_client._render_filter(
        'datafield1 = "{domain}" or datafield3 = "{domain}"', "obltub.ru"
    )
    assert result == 'datafield1 = "obltub.ru" or datafield3 = "obltub.ru"'


def test_filter_strips_quotes_from_domain():
    """Домен уходит внутрь строки фильтра — кавычки в нём ломали бы запрос."""
    result = siem_client._render_filter('datafield1 = "{domain}"', 'evil" or 1=1 "')
    assert '"' not in result.replace('datafield1 = "', "", 1)[:-1]


def test_filter_without_placeholder_used_as_is():
    result = siem_client._render_filter("event_src.title = 'skydns'", "obltub.ru")
    assert result == "event_src.title = 'skydns'"


# --- тело запроса ---------------------------------------------------------

def test_group_query_has_filter_group_and_period():
    body = siem_client._build_group_query(
        query_filter='datafield1 = "obltub.ru"',
        group_field="dst.host",
        time_from=TIME_FROM,
        time_to=TIME_TO,
    )
    assert body["filter"]["where"] == 'datafield1 = "obltub.ru"'
    assert body["filter"]["groupBy"] == ["dst.host"]
    assert "dst.host" in body["filter"]["select"]
    assert body["timeFrom"] == int(TIME_FROM.timestamp())
    assert body["timeTo"] == int(TIME_TO.timestamp())


# --- разбор ответа --------------------------------------------------------

def test_parse_plain_rows():
    payload = {
        "totalCount": 2,
        "events": [
            {"dst.host": "10.0.12.34", "count": 17},
            {"dst.host": "10.0.12.99", "count": 3},
        ],
    }
    hosts = siem_client._parse_group_rows(payload, "dst.host")
    assert [(h.address, h.events_count) for h in hosts] == [
        ("10.0.12.34", 17), ("10.0.12.99", 3)
    ]


def test_parse_sorts_by_event_count_desc():
    payload = {"events": [
        {"dst.host": "10.0.0.1", "count": 2},
        {"dst.host": "10.0.0.2", "count": 50},
    ]}
    hosts = siem_client._parse_group_rows(payload, "dst.host")
    assert hosts[0].address == "10.0.0.2"


def test_parse_nested_fields_shape():
    payload = {"events": [{"fields": {"dst.host": "192.168.1.5"}, "count": 4}]}
    hosts = siem_client._parse_group_rows(payload, "dst.host")
    assert hosts[0].address == "192.168.1.5"
    assert hosts[0].events_count == 4


def test_parse_group_values_shape():
    payload = {"events": [{"groupValues": ["172.16.0.9"], "aggregateValue": 8}]}
    hosts = siem_client._parse_group_rows(payload, "dst.host")
    assert hosts[0].address == "172.16.0.9"
    assert hosts[0].events_count == 8


def test_parse_merges_duplicate_addresses():
    payload = {"events": [
        {"dst.host": "10.0.0.1", "count": 2},
        {"dst.host": "10.0.0.1", "count": 3},
    ]}
    hosts = siem_client._parse_group_rows(payload, "dst.host")
    assert len(hosts) == 1
    assert hosts[0].events_count == 5


def test_parse_skips_rows_without_group_field():
    payload = {"events": [{"src.ip": "10.0.0.1"}, {"dst.host": "10.0.0.2"}]}
    hosts = siem_client._parse_group_rows(payload, "dst.host")
    assert [h.address for h in hosts] == ["10.0.0.2"]


def test_parse_empty_response():
    assert siem_client._parse_group_rows({"totalCount": 0, "events": []}, "dst.host") == []


def test_response_rows_reads_both_shapes():
    assert siem_client._response_rows({"events": [{"a": 1}]}) == [{"a": 1}]
    assert siem_client._response_rows({"rows": [{"a": 1}]}) == [{"a": 1}]
    assert siem_client._response_rows({"totalCount": 0}) == []


# --- сетевая часть: цепочка редиректов и заголовки ------------------------

def test_client_follows_redirects():
    """Вход в SIEM — это цепочка OIDC из нескольких переходов.

    Раньше редиректы были отключены, и вручную проходился ровно один шаг:
    на втором переходе вход обрывался с HTTPError.
    """
    config = siem_client.SiemConfig(base_url="https://siem.local")
    client = siem_client.SiemClient(config)
    handlers = [type(h).__name__ for h in client._opener.handlers]
    assert "HTTPCookieProcessor" in handlers
    # Штатный обработчик редиректов должен остаться на месте.
    assert any("Redirect" in name for name in handlers)


def test_default_timeout_is_generous():
    """Сгруппированный запрос за сутки в 30 секунд не укладывался."""
    assert siem_client.SiemConfig().timeout >= 120


class _FakeResponse:
    def __init__(self, body: str = "", status: int = 200):
        self._body = body.encode()
        self.status = status

    def read(self) -> bytes:
        return self._body


LOGIN_FORM_HTML = (
    '<form method="post" action="https://siem.local/signin-oidc">'
    '<input name="code" value="abc" />'
    '<input name="id_token" value="x&amp;y" />'
    '</form>'
)


def _record_session_login(monkeypatch):
    """Пройти вход по сессии на подставном opener и вернуть список запросов."""
    config = siem_client.SiemConfig(
        base_url="https://siem.local", username="op", password="secret"
    )
    client = siem_client.SiemClient(config)
    sent = []

    bodies = iter([
        _FakeResponse("{}"),               # POST /ui/login на Core
        _FakeResponse(LOGIN_FORM_HTML),    # GET формы авторизации
        _FakeResponse(""),                 # POST формы
        _FakeResponse('{"version": "26"}'),  # контрольный system_info
    ])

    def fake_open(request, timeout=None):
        sent.append(request)
        return next(bodies)

    monkeypatch.setattr(client._opener, "open", fake_open)
    client.login()
    return sent


def test_session_login_talks_to_core_port_then_portal(monkeypatch):
    sent = _record_session_login(monkeypatch)
    urls = [r.full_url for r in sent]
    assert urls[0] == "https://siem.local:3334/ui/login"
    assert urls[1].startswith("https://siem.local/account/login?returnUrl=")
    assert urls[2] == "https://siem.local/signin-oidc"
    assert urls[3] == "https://siem.local" + siem_client.PATH_SYSTEM_INFO


def test_login_form_is_requested_as_html(monkeypatch):
    """Страницу входа отдают в HTML — Accept: application/json был неуместен."""
    sent = _record_session_login(monkeypatch)
    assert "html" in sent[1].get_header("Accept")


def test_login_form_hidden_fields_are_posted_back(monkeypatch):
    sent = _record_session_login(monkeypatch)
    posted = sent[2].data.decode()
    assert "code=abc" in posted
    # HTML-сущности в скрытых полях должны вернуться расшифрованными.
    assert "id_token=x%26y" in posted


def _search(monkeypatch, payload: dict, limit: int = 500):
    config = siem_client.SiemConfig(
        base_url="https://siem.local", username="op", password="secret",
        limit=limit,
    )
    client = siem_client.SiemClient(config)
    sent = []

    def fake_open(request, timeout=None):
        sent.append(request)
        return _FakeResponse(json.dumps(payload))

    monkeypatch.setattr(client._opener, "open", fake_open)
    result = client.search_hosts(
        "obltub.ru", TIME_FROM, TIME_TO,
        'datafield1 = "{domain}" or datafield3 = "{domain}"', "dst.host",
    )
    return result, sent[0]


def test_search_posts_to_events_endpoint_with_limit(monkeypatch):
    _, request = _search(monkeypatch, {"totalCount": 0, "events": []})
    assert request.full_url.startswith(
        "https://siem.local" + siem_client.PATH_EVENTS + "?"
    )
    assert "limit=500" in request.full_url and "offset=0" in request.full_url
    assert request.get_header("Content-type").startswith("application/json")


def test_search_body_carries_filter_group_and_period(monkeypatch):
    _, request = _search(monkeypatch, {"totalCount": 0, "events": []})
    body = json.loads(request.data.decode())
    assert body["filter"]["where"] == \
        'datafield1 = "obltub.ru" or datafield3 = "obltub.ru"'
    assert body["filter"]["groupBy"] == ["dst.host"]
    assert body["timeFrom"] == int(TIME_FROM.timestamp())


def test_search_reports_truncation_at_the_limit(monkeypatch):
    """Ответ ровно в предел — признак, что SIEM отдал не всё."""
    rows = [{"dst.host": f"10.0.0.{i}", "count": 1} for i in range(10)]
    result, _ = _search(monkeypatch, {"totalCount": 10, "events": rows}, limit=10)
    assert result.truncated is True


def test_search_does_not_cry_truncation_below_the_limit(monkeypatch):
    rows = [{"dst.host": "10.0.0.1", "count": 1}]
    result, _ = _search(monkeypatch, {"totalCount": 1, "events": rows}, limit=10)
    assert result.truncated is False


def test_session_login_sends_credentials_as_json(monkeypatch):
    sent = _record_session_login(monkeypatch)
    payload = json.loads(sent[0].data.decode())
    assert payload == {
        "authType": 0, "username": "op", "password": "secret", "newPassword": None
    }


def test_extract_error_message_from_siem_body():
    raw = '{"errors": [{"error": {"message": "Некорректный PDQL"}}, {"error": {}}]}'
    assert siem_client._extract_error(raw) == "Некорректный PDQL"


def test_extract_error_from_non_json():
    assert "502" in siem_client._extract_error("<html>502 Bad Gateway</html>")
