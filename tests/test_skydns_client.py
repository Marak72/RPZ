"""Тесты разбора статистики SkyDNS: отбор категорий, JSON и CSV."""
import pytest

from app.services import skydns_client
from app.services.skydns_client import SkydnsError

CATEGORIES = ["malware", "botnet", "phishing"]


# --- отбор категорий безопасности -----------------------------------------

def test_category_from_settings_list_matches():
    assert skydns_client.is_security_category("malware", "", CATEGORIES)


def test_category_matches_case_insensitively():
    assert skydns_client.is_security_category("MALWARE", "", CATEGORIES)


def test_category_matched_by_title_hint():
    """Кода в списке нет, но название явно про угрозу."""
    assert skydns_client.is_security_category("cat42", "Фишинг", [])


def test_ordinary_category_is_skipped():
    assert not skydns_client.is_security_category("news", "Новости", CATEGORIES)


def test_empty_category_is_skipped():
    assert not skydns_client.is_security_category("", "", CATEGORIES)


# --- разбор строк ---------------------------------------------------------

def test_parse_rows_reads_typical_fields():
    rows = [{"domain": "Evil.RU", "category": "malware", "requests": "42",
             "blocks": "40"}]
    stats = skydns_client.parse_rows(rows)
    assert stats[0].domain == "evil.ru"
    assert stats[0].category == "malware"
    assert stats[0].requests == 42
    assert stats[0].blocks == 40


def test_parse_rows_accepts_russian_headers():
    stats = skydns_client.parse_rows([{"Домен": "bad.ru", "Категория": "malware",
                                       "Запросы": "7"}])
    assert stats[0].domain == "bad.ru"
    assert stats[0].requests == 7


def test_parse_rows_honours_custom_field_map():
    rows = [{"site": "bad.ru", "cat": "malware", "hits": "5"}]
    stats = skydns_client.parse_rows(
        rows, {"domain": "site", "category": "cat", "requests": "hits"}
    )
    assert stats[0].domain == "bad.ru"
    assert stats[0].requests == 5


def test_parse_rows_extracts_host_from_url():
    stats = skydns_client.parse_rows([{"domain": "https://bad.ru/path?a=1"}])
    assert stats[0].domain == "bad.ru"


def test_parse_rows_strips_wildcard_and_port():
    stats = skydns_client.parse_rows([{"domain": "*.bad.ru:8080"}])
    assert stats[0].domain == "bad.ru"


def test_parse_rows_skips_non_domains():
    stats = skydns_client.parse_rows([{"domain": "localhost"}, {"domain": ""},
                                      {"domain": "ok.ru"}])
    assert [s.domain for s in stats] == ["ok.ru"]


# --- поиск строк в ответе произвольной формы ------------------------------

def test_rows_found_in_plain_list():
    assert skydns_client._rows_from_payload([{"domain": "a.ru"}])


def test_rows_found_under_data_key():
    rows = skydns_client._rows_from_payload({"data": [{"domain": "a.ru"}]})
    assert rows[0]["domain"] == "a.ru"


def test_rows_found_in_nested_wrapper():
    rows = skydns_client._rows_from_payload(
        {"result": {"items": [{"domain": "a.ru"}]}}
    )
    assert rows[0]["domain"] == "a.ru"


def test_rows_found_in_domain_keyed_map():
    rows = skydns_client._rows_from_payload({"a.ru": {"category": "malware"}})
    assert rows[0]["domain"] == "a.ru"


# --- CSV ------------------------------------------------------------------

def test_parse_csv_semicolon_and_bom():
    data = "﻿domain;category;requests\r\nbad.ru;malware;42\r\n".encode("utf-8")
    stats = skydns_client.parse_csv(data)
    assert stats[0].domain == "bad.ru"
    assert stats[0].requests == 42


def test_parse_csv_comma_delimiter():
    data = b"domain,category,requests\nbad.ru,malware,7\n"
    stats = skydns_client.parse_csv(data)
    assert stats[0].domain == "bad.ru"


def test_parse_csv_cp1251_russian_headers():
    data = "Домен;Категория;Запросы\r\nbad.ru;Вредоносное ПО;3\r\n".encode("cp1251")
    stats = skydns_client.parse_csv(data)
    assert stats[0].domain == "bad.ru"
    assert stats[0].category == "Вредоносное ПО"


def test_parse_csv_without_domain_column_is_rejected():
    data = b"foo;bar\r\n1;2\r\n"
    with pytest.raises(SkydnsError):
        skydns_client.parse_csv(data)
