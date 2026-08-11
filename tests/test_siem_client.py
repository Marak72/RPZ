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


def test_search_body_carries_filter_and_period(monkeypatch):
    _, request = _search(monkeypatch, {"totalCount": 0, "events": []})
    body = json.loads(request.data.decode())
    assert body["filter"]["where"] == \
        'datafield1 = "obltub.ru" or datafield3 = "obltub.ru"'
    assert body["timeFrom"] == int(TIME_FROM.timestamp())


def test_search_does_not_ask_siem_to_group(monkeypatch):
    """С группировкой SIEM отдавал по строке на отметку времени.

    Один DNS-запрос — это пара событий (receive от станции и send наверх),
    и представителем пары оказывалось событие с пустым src.ip: события
    находились, адреса — нет. Сводим по адресам сами.
    """
    _, request = _search(monkeypatch, {"totalCount": 0, "events": []})
    body = json.loads(request.data.decode())
    assert body["filter"]["groupBy"] == []
    assert body["filter"]["aggregateBy"] == []


def test_search_asks_for_the_other_address_fields_too(monkeypatch):
    """select — это проекция; лишние адресные колонки ничего не стоят."""
    _, request = _search(monkeypatch, {"totalCount": 0, "events": []})
    select = json.loads(request.data.decode())["filter"]["select"]
    assert select[0] == "dst.host"          # настроенное поле — первым
    assert "src.ip" in select and "src.host" in select
    # Но всю таксономию не тянем: на сотнях доменов это мегабайты.
    assert len(select) < 40


def test_search_reports_truncation_when_the_cap_stops_it(monkeypatch):
    """Событий больше, чем разрешено прочитать — часть хостов не увидим."""
    rows = [{"dst.host": f"10.0.0.{i}", "count": 1} for i in range(10)]
    result, _ = _search(monkeypatch, {"totalCount": 4000, "events": rows}, limit=10)
    assert result.truncated is True
    assert result.events_read == 10


def test_search_does_not_cry_truncation_when_everything_is_read(monkeypatch):
    rows = [{"dst.host": "10.0.0.1", "count": 1}]
    result, _ = _search(monkeypatch, {"totalCount": 1, "events": rows}, limit=10)
    assert result.truncated is False
    assert result.events_read == 1


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


# --- поле группировки может быть не одно ----------------------------------

def test_group_field_accepts_a_list():
    """Адрес конечного хоста в разных источниках лежит в разных полях."""
    assert siem_client._group_fields("src.ip, src.host") == ["src.ip", "src.host"]
    assert siem_client._group_fields(" dst.host ") == ["dst.host"]
    assert siem_client._group_fields("") == ["src.ip"]


def test_query_groups_by_every_listed_field():
    body = siem_client._build_group_query(
        query_filter='datafield1 = "x"', group_field="src.ip, src.host",
        time_from=TIME_FROM, time_to=TIME_TO,
    )
    assert body["filter"]["groupBy"] == ["src.ip", "src.host"]
    assert body["filter"]["select"] == ["src.ip", "src.host", "time"]
    # Считаем по первому полю: агрегат в запросе может быть только один.
    assert body["filter"]["aggregateBy"][0]["field"] == "src.ip"


def test_first_filled_field_becomes_the_address():
    payload = {"events": [
        {"src.ip": "", "src.host": "wks-14", "count": 2},
        {"src.ip": "10.0.0.7", "src.host": "wks-15", "count": 5},
    ]}
    hosts = siem_client._parse_group_rows(payload, "src.ip, src.host")
    assert [h.address for h in hosts] == ["10.0.0.7", "wks-14"]


def test_null_string_is_not_an_address():
    """SIEM отдаёт незаполненное поле строкой 'null' — это не адрес."""
    payload = {"events": [{"src.ip": "null", "src.host": "wks-1", "count": 1}]}
    assert siem_client._parse_group_rows(payload, "src.ip, src.host")[0].address \
        == "wks-1"


def test_generated_aggregate_column_is_counted():
    """Колонку агрегата SIEM называет по самой функции — COUNT(src.ip)."""
    payload = {"events": [{"src.ip": "10.0.0.1", "COUNT(src.ip)": 42}]}
    assert siem_client._parse_group_rows(payload, "src.ip")[0].events_count == 42


# --- диагностика: где в событии лежит адрес --------------------------------

#: Строка ровно того вида, что приходит с боевого SIEM: событие целиком,
#: со служебным _meta, и с незаполненным src.ip.
REAL_META = {
    "id": "de5348fc-952d-11f1-9323-005056a7e62f",
    "time": "2026-08-11T02:39:26.1260000Z",
    "assetIds": None,
    "site_alias": "unknown site_id=null",
    "site_is_deleted": True,
}
REAL_ROWS = [
    {"src.ip": None, "dst.ip": "10.14.2.51", "dst.host": "wks-buh-07",
     "datafield1": "autodesk.com", "datafield3": None,
     "event_src.host": "skydns-gw", "src.port": None,
     "time": "2026-08-11T02:39:26.1260000Z", "_meta": REAL_META},
    {"src.ip": None, "dst.ip": "10.14.2.60", "dst.host": None,
     "datafield1": "autodesk.com", "datafield3": None,
     "event_src.host": "skydns-gw",
     "time": "2026-08-11T02:38:54.8630000Z", "_meta": REAL_META},
]
REAL_FILTER = 'datafield1 = "autodesk.com" or datafield3 = "autodesk.com"'


def test_filled_fields_ignores_empty_values_and_meta():
    filled = {item["field"]: item for item in siem_client._filled_fields(REAL_ROWS)}
    assert "src.ip" not in filled       # null
    assert "src.port" not in filled     # null
    assert "_meta" not in filled        # служебное
    assert filled["dst.ip"]["rows"] == 2
    assert filled["dst.host"]["rows"] == 1
    assert filled["dst.ip"]["sample"] == "10.14.2.51"


def test_filled_fields_are_sorted_by_how_often_they_are_filled():
    names = [item["field"] for item in siem_client._filled_fields(REAL_ROWS)]
    assert names.index("dst.ip") < names.index("dst.host")


def test_candidates_offer_fields_that_look_like_an_address():
    names = [item["field"]
             for item in siem_client._address_candidates(
                 REAL_ROWS, ["src.ip"], REAL_FILTER)]
    assert "dst.ip" in names and "dst.host" in names


def test_candidates_skip_the_fields_from_the_filter():
    """В datafield1 лежит проверяемый домен — он тоже похож на имя узла."""
    names = [item["field"]
             for item in siem_client._address_candidates(
                 REAL_ROWS, ["src.ip"], REAL_FILTER)]
    assert "datafield1" not in names


def test_candidates_skip_time_and_the_configured_field():
    names = [item["field"]
             for item in siem_client._address_candidates(
                 REAL_ROWS, ["dst.ip"], REAL_FILTER)]
    assert "time" not in names and "dst.ip" not in names


def test_real_response_yields_no_hosts_by_src_ip():
    """Именно это и происходило: события есть, а поле пустое."""
    payload = {"totalCount": 22, "events": REAL_ROWS}
    assert siem_client._parse_group_rows(payload, "src.ip") == []


def test_switching_the_field_recovers_the_hosts():
    payload = {"totalCount": 22, "events": REAL_ROWS}
    hosts = siem_client._parse_group_rows(payload, "dst.ip, dst.host")
    assert [h.address for h in hosts] == ["10.14.2.51", "10.14.2.60"]


def test_probe_query_asks_for_everything_and_does_not_group():
    """Диагностика видит поля, только если запросила их в select."""
    body = siem_client._build_group_query(
        query_filter=REAL_FILTER, group_field="src.ip",
        time_from=TIME_FROM, time_to=TIME_TO,
        select=list(siem_client.TAXONOMY_FIELDS), group_by=[],
    )
    assert "dst.ip" in body["filter"]["select"]
    assert len(body["filter"]["select"]) > 150
    assert body["filter"]["groupBy"] == []
    # Без группировки агрегат не имеет смысла и SIEM его не ждёт.
    assert body["filter"]["aggregateBy"] == []


def test_address_shape_check():
    assert siem_client._looks_like_address("10.14.2.51")
    assert siem_client._looks_like_address("wks-buh-07")
    assert siem_client._looks_like_address("fe80::1")
    assert not siem_client._looks_like_address("")
    assert not siem_client._looks_like_address("Вход выполнен успешно")


# --- пара событий DNS-сервера ---------------------------------------------
#
# Один DNS-запрос порождает два события: сервер принял запрос от станции
# (action=receive, адрес станции в src.ip) и переслал его вышестоящему
# резолверу (action=send, src.ip пуст, в dst.ip внешний адрес).

DNS_RECEIVE = {
    "action": "receive", "src.ip": "10.61.50.40", "src.host": "10.61.50.40",
    "dst.ip": None, "dst.host": None, "event_src.host": "10.12.7.3",
    "recv_ipv4": "10.12.7.3", "datafield3": "autodesk.com",
    "datafield6": "update.delivery.autodesk.com",
    "object.value": "update.delivery.autodesk.com",
    "taxonomy_version": "27.0.859-release-27.0",
    "time": "2026-08-11T02:39:26Z", "_meta": {"id": "de53487a"},
}
DNS_SEND = dict(DNS_RECEIVE, action="send", **{
    "src.ip": None, "src.host": None,
    "dst.ip": "109.233.224.100", "dst.host": "109.233.224.100",
})
DNS_ROWS = [
    DNS_RECEIVE, DNS_SEND, DNS_RECEIVE, DNS_SEND,
    dict(DNS_RECEIVE, **{"src.ip": "10.83.67.40", "src.host": "10.83.67.40"}),
    dict(DNS_RECEIVE, **{"src.ip": "10.170.9.214", "src.host": "10.170.9.214"}),
]
DNS_FILTER = 'datafield1 = "autodesk.com" or datafield3 = "autodesk.com"'


def test_events_without_the_address_are_skipped_not_fatal():
    """Событие send адреса станции не несёт — оно просто пропускается.

    Раньше именно такое событие SIEM выбирал представителем группы, и
    поиск не находил ни одного хоста при непустом числе событий.
    """
    hosts = siem_client._parse_group_rows({"events": DNS_ROWS}, "src.ip")
    assert [(h.address, h.events_count) for h in hosts] == [
        ("10.61.50.40", 2), ("10.170.9.214", 1), ("10.83.67.40", 1)
    ]


def test_external_resolver_is_marked_as_such():
    """dst.ip в этих событиях — вышестоящий DNS, а не рабочая станция."""
    found = {i["field"]: i["kind"] for i in siem_client._address_candidates(
        DNS_ROWS, ["src.ip"], DNS_FILTER, "autodesk.com")}
    assert found["dst.ip"] == "внешний адрес"
    assert found["event_src.host"] == "внутренний адрес"


def test_internal_addresses_come_before_external_ones():
    kinds = [i["kind"] for i in siem_client._address_candidates(
        DNS_ROWS, ["src.ip"], DNS_FILTER, "autodesk.com")]
    assert kinds.index("внутренний адрес") < kinds.index("внешний адрес")


def test_version_strings_are_not_offered_as_addresses():
    """taxonomy_version выглядит как имя узла, но адресом не является."""
    names = [i["field"] for i in siem_client._address_candidates(
        DNS_ROWS, ["src.ip"], DNS_FILTER, "autodesk.com")]
    assert "taxonomy_version" not in names


def test_fields_holding_the_queried_domain_are_not_offered():
    """В datafield6 и object.value лежит само запрошенное имя."""
    names = [i["field"] for i in siem_client._address_candidates(
        DNS_ROWS, ["src.ip"], DNS_FILTER, "autodesk.com")]
    assert "datafield6" not in names and "object.value" not in names


def test_address_kind_recognises_private_and_public():
    assert siem_client._address_kind("10.61.50.40") == "внутренний адрес"
    assert siem_client._address_kind("192.168.1.1") == "внутренний адрес"
    assert siem_client._address_kind("109.233.224.100") == "внешний адрес"
    assert siem_client._address_kind("wks-buh-07") == "имя узла"


# --- дочитывание событий страницами ---------------------------------------

def _paged_client(total: int, cap: int = 20000):
    """Клиент с подставным SIEM, который честно отдаёт страницы."""
    config = siem_client.SiemConfig(
        base_url="https://siem.local", username="op", password="p", limit=cap,
    )
    client = siem_client.SiemClient(config)
    calls = []

    def fake_open(request, timeout=None):
        from urllib.parse import parse_qs, urlsplit

        params = parse_qs(urlsplit(request.full_url).query)
        offset = int(params["offset"][0])
        size = int(params["limit"][0])
        calls.append({
            "offset": offset, "limit": size,
            "token": (params.get("token") or [""])[0],
            "body": json.loads(request.data.decode()),
        })
        rows = [{"src.ip": f"10.0.{(offset + i) // 250}.{(offset + i) % 250}"}
                for i in range(max(0, min(size, total - offset)))]
        return _FakeResponse(json.dumps(
            {"totalCount": total, "token": "tk-1", "events": rows}
        ))

    monkeypatch_open(client, fake_open)
    return client, calls


def monkeypatch_open(client, fake_open):
    client._opener.open = fake_open


def _run_search(client):
    return client.search_hosts(
        "obltub.ru", TIME_FROM, TIME_TO,
        'datafield1 = "{domain}"', "src.ip",
    )


def test_events_are_read_page_by_page_until_the_end():
    """Одной страницы мало: хосты распределены по выборке неравномерно."""
    client, calls = _paged_client(total=2300)
    result = _run_search(client)

    assert [c["offset"] for c in calls] == [0, 1000, 2000]
    assert result.events_read == 2300
    assert result.truncated is False
    assert len(result.hosts) == 2300


def test_pages_after_the_first_carry_the_token():
    """Токен закрепляет выборку, иначе страницы поедут при новых событиях."""
    client, calls = _paged_client(total=1500)
    _run_search(client)
    assert calls[0]["token"] == ""
    assert calls[1]["token"] == "tk-1"


def test_pages_after_the_first_drop_the_upper_time_bound():
    client, calls = _paged_client(total=1500)
    _run_search(client)
    assert calls[0]["body"]["timeTo"] == int(TIME_TO.timestamp())
    assert calls[1]["body"]["timeTo"] is None


def test_reading_stops_at_the_cap_and_says_so():
    client, calls = _paged_client(total=50000, cap=2500)
    result = _run_search(client)
    assert result.events_read == 2500
    assert result.truncated is True
    # Последняя страница просит ровно остаток, а не целую тысячу.
    assert calls[-1]["limit"] == 500


def test_empty_page_stops_the_loop():
    """Если SIEM соврал про totalCount, цикл не должен стать вечным."""
    client, calls = _paged_client(total=0)
    result = _run_search(client)
    assert len(calls) == 1
    assert result.events_read == 0


# --- пачка доменов одним запросом -----------------------------------------

def test_filter_for_a_batch_joins_conditions_with_or():
    """Используются только = и or: что они работают, проверено на практике."""
    result = siem_client._render_filter_many(
        'datafield1 = "{domain}" or datafield3 = "{domain}"',
        ["a.ru", "b.ru"],
    )
    assert result == (
        '(datafield1 = "a.ru" or datafield3 = "a.ru")'
        ' or (datafield1 = "b.ru" or datafield3 = "b.ru")'
    )


def test_events_are_attributed_back_to_their_domains():
    rows = [
        {"datafield3": "autodesk.com", "src.ip": "10.0.0.1"},
        {"datafield3": "evil.ru", "src.ip": "10.0.0.2"},
    ]
    out = siem_client._attribute(rows, ["autodesk.com", "evil.ru"],
                                 siem_client.DOMAIN_FIELDS)
    assert [r["src.ip"] for r in out["autodesk.com"]] == ["10.0.0.1"]
    assert [r["src.ip"] for r in out["evil.ru"]] == ["10.0.0.2"]


def test_subdomain_event_belongs_to_the_requested_domain():
    """В datafield6 лежит полное имя, а спрашивали базовое."""
    rows = [{"datafield6": "update.delivery.autodesk.com", "src.ip": "10.0.0.1"}]
    out = siem_client._attribute(rows, ["autodesk.com"],
                                 siem_client.DOMAIN_FIELDS)
    assert len(out["autodesk.com"]) == 1


def test_the_most_specific_requested_domain_wins():
    """Если спрошены и корень, и поддомен, событие достаётся поддомену."""
    rows = [{"datafield6": "update.delivery.autodesk.com", "src.ip": "10.0.0.1"}]
    out = siem_client._attribute(
        rows, ["autodesk.com", "delivery.autodesk.com"],
        siem_client.DOMAIN_FIELDS,
    )
    assert out["autodesk.com"] == []
    assert len(out["delivery.autodesk.com"]) == 1


def test_similar_name_is_not_attributed():
    """Совпадение по границе метки: evilautodesk.com — чужой домен."""
    rows = [{"datafield3": "evilautodesk.com", "src.ip": "10.0.0.1"}]
    out = siem_client._attribute(rows, ["autodesk.com"],
                                 siem_client.DOMAIN_FIELDS)
    assert out["autodesk.com"] == []


def test_every_requested_domain_gets_an_entry():
    """Домен без событий тоже должен получить результат, иначе он не будет
    отмечен проверенным и попадёт в следующий прогон."""
    out = siem_client._attribute([], ["a.ru", "b.ru"], siem_client.DOMAIN_FIELDS)
    assert set(out) == {"a.ru", "b.ru"}


def test_filter_fields_are_taken_from_the_template():
    assert siem_client._filter_fields(
        'datafield1 = "{domain}" or datafield3 = "{domain}"'
    ) == ["datafield1", "datafield3"]


def test_search_many_splits_results_per_domain(monkeypatch):
    config = siem_client.SiemConfig(base_url="https://siem.local", limit=5000)
    client = siem_client.SiemClient(config)
    sent = []

    def fake_open(request, timeout=None):
        sent.append(json.loads(request.data.decode()))
        rows = [
            {"datafield3": "a.ru", "src.ip": "10.0.0.1"},
            {"datafield3": "a.ru", "src.ip": "10.0.0.1"},
            {"datafield3": "b.ru", "src.ip": "10.0.0.2"},
            {"datafield3": "c.ru", "src.ip": "10.0.0.3"},
        ]
        return _FakeResponse(json.dumps({"totalCount": 4, "events": rows}))

    monkeypatch.setattr(client._opener, "open", fake_open)
    results = client.search_many(
        ["a.ru", "b.ru"], TIME_FROM, TIME_TO,
        'datafield1 = "{domain}" or datafield3 = "{domain}"', "src.ip",
    )

    # Один запрос на оба домена — ради этого всё и затевалось.
    assert len(sent) == 1
    assert set(results) == {"a.ru", "b.ru"}
    assert results["a.ru"].hosts[0].address == "10.0.0.1"
    assert results["a.ru"].events_read == 2
    assert results["b.ru"].hosts[0].address == "10.0.0.2"
    # Чужое событие (c.ru) не приписано никому из запрошенных.
    assert sum(r.events_read for r in results.values()) == 3


def test_search_many_asks_for_the_name_fields():
    """Без них события нечем разложить обратно по доменам."""
    body = siem_client._build_group_query(
        query_filter="x", group_field="src.ip",
        time_from=TIME_FROM, time_to=TIME_TO,
        select=siem_client._select_for(["src.ip"]) + list(siem_client.DOMAIN_FIELDS),
        group_by=[],
    )
    for name in ("datafield1", "datafield3", "datafield6", "object.value"):
        assert name in body["filter"]["select"], name


def test_search_many_ignores_empty_input():
    client = siem_client.SiemClient(siem_client.SiemConfig(base_url="https://s"))
    assert client.search_many([], TIME_FROM, TIME_TO, "x", "src.ip") == {}
