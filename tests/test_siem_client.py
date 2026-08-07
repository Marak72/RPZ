"""Тесты клиента MaxPatrol SIEM: сборка запроса и разбор ответа.

Сеть не задействуется — проверяются только чистые функции.
"""
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


def test_extract_error_message_from_siem_body():
    raw = '{"errors": [{"error": {"message": "Некорректный PDQL"}}, {"error": {}}]}'
    assert siem_client._extract_error(raw) == "Некорректный PDQL"


def test_extract_error_from_non_json():
    assert "502" in siem_client._extract_error("<html>502 Bad Gateway</html>")
