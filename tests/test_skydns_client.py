"""Тесты клиента Proxy Stat API SkyDNS.

Сеть не задействуется: HTTP-вызов подменяется, проверяются сборка запроса
и разбор документированных форматов ответа.
"""
import json
from datetime import date

import pytest

from app.services.skydns.lib import skydns_client
from app.services.skydns.lib.skydns_client import (
    Category,
    SkydnsClient,
    SkydnsConfig,
    SkydnsError,
)

START = date(2026, 8, 1)
END = date(2026, 8, 7)


def _client(monkeypatch, response, capture=None):
    """Клиент с подменённым транспортом: возвращает заданный ответ."""
    config = SkydnsConfig(
        user_id="123", token="secret",
        profile_ids="0, 1121", timezone="Asia/Yekaterinburg",
    )
    client = SkydnsClient(config)

    def fake_call(method, payload):
        if capture is not None:
            capture.append((method, payload))
        return response

    monkeypatch.setattr(client, "_call", fake_call)
    return client


# --- адрес и авторизация --------------------------------------------------

def test_url_follows_documented_template():
    client = SkydnsClient(SkydnsConfig(user_id="123", token="t"))
    assert client._url("get_domains_activity") == (
        "https://skydns.ru/cabinet/rest_api/statistics/users/123"
        "/proxy/v2/get_domains_activity/"
    )


def test_url_honours_custom_base():
    client = SkydnsClient(SkydnsConfig(base_url="https://dns.local", user_id="7",
                                       token="t"))
    assert client._url("get_activity").startswith("https://dns.local/cabinet/")


def test_not_configured_without_token():
    assert not SkydnsConfig(user_id="1").is_configured
    assert not SkydnsConfig(token="t").is_configured
    assert SkydnsConfig(user_id="1", token="t").is_configured


def test_call_without_config_is_rejected():
    with pytest.raises(SkydnsError):
        SkydnsClient(SkydnsConfig())._call("get_activity", {})


# --- аргументы периода ----------------------------------------------------

def test_period_range_carries_start_and_end():
    payload = skydns_client.build_period(START, END, timezone="Europe/Moscow")
    assert payload["period"] == "range"
    assert payload["start"] == "2026-08-01"
    assert payload["end"] == "2026-08-07"
    assert payload["timezone"] == "Europe/Moscow"


def test_period_range_requires_start():
    with pytest.raises(SkydnsError):
        skydns_client.build_period(None, END)


def test_period_date_uses_single_day():
    payload = skydns_client.build_period(START, period="date")
    assert payload["date"] == "2026-08-01"
    assert "start" not in payload


def test_profile_ids_parsed_into_list():
    config = SkydnsConfig(profile_ids="0, 1121 ; 1470")
    assert config.profile_list() == [0, 1121, 1470]


def test_empty_profile_ids_means_all_profiles():
    assert SkydnsConfig().profile_list() == []
    payload = skydns_client.build_period(START, END, profile_ids=[])
    assert "profile_ids" not in payload


# --- get_categories_activity ---------------------------------------------

def test_categories_parsed_with_danger_flag(monkeypatch):
    response = [
        {"cat": {"id": 3, "title": "Malware", "is_dangerous": True},
         "requests": 100, "blocks": 90},
        {"cat": {"id": 49, "title": "Computers & Internet", "is_dangerous": False},
         "requests": 16471215, "blocks": 403145},
    ]
    cats = _client(monkeypatch, response).categories(START, END)
    assert [(c.id, c.is_dangerous) for c in cats] == [(3, True), (49, False)]
    assert cats[0].title == "Malware"
    assert cats[1].requests == 16471215


def test_categories_request_carries_lang_and_profiles(monkeypatch):
    capture = []
    _client(monkeypatch, [], capture).categories(START, END, lang="ru")
    method, payload = capture[0]
    assert method == "get_categories_activity"
    assert payload["lang"] == "ru"
    assert payload["profile_ids"] == [0, 1121]
    assert payload["timezone"] == "Asia/Yekaterinburg"


def test_categories_reject_unexpected_shape(monkeypatch):
    with pytest.raises(SkydnsError):
        _client(monkeypatch, {"oops": 1}).categories(START, END)


# --- get_domains_activity -------------------------------------------------

def test_domains_parsed(monkeypatch):
    response = [{"domain": "google.com", "requests": 126407526,
                 "blocks": 634145, "cat_ids": [49]}]
    stats = _client(monkeypatch, response).domains(START, END)
    assert stats[0].domain == "google.com"
    assert stats[0].requests == 126407526
    assert stats[0].cat_ids == [49]


def test_domains_request_filters_by_categories(monkeypatch):
    capture = []
    _client(monkeypatch, [], capture).domains(START, END, cats=[3, 4], limit=500)
    method, payload = capture[0]
    assert method == "get_domains_activity"
    assert payload["cats"] == [3, 4]
    assert payload["limit"] == 500
    assert payload["order_by"] == "-visits"


def test_domains_skip_rows_without_domain(monkeypatch):
    response = [{"domain": ""}, {"requests": 5}, {"domain": "ok.ru"}]
    stats = _client(monkeypatch, response).domains(START, END)
    assert [s.domain for s in stats] == ["ok.ru"]


# --- get_devices_activity -------------------------------------------------

def test_devices_parsed_and_gateway_detected(monkeypatch):
    response = [
        {"token": 12345678, "ipv4": ["1.1.1.2", "1.1.1.3"], "ipv6": ["::"],
         "secure": True, "requests": 936755, "blocks": 6394},
        {"token": 0, "ipv4": ["1.1.1.1"], "ipv6": ["::"],
         "secure": False, "requests": 100, "blocks": 1},
    ]
    devices = _client(monkeypatch, response).devices(START, END,
                                                     domains=["evil.ru"])
    assert devices[0].is_gateway is False
    assert devices[0].addresses == ["1.1.1.2", "1.1.1.3"]
    # Заглушка ipv6 "::" в адреса не попадает.
    assert "::" not in devices[0].addresses
    assert devices[1].is_gateway is True


def test_devices_request_carries_domain_filter(monkeypatch):
    capture = []
    _client(monkeypatch, [], capture).devices(START, END, domains=["evil.ru"])
    method, payload = capture[0]
    assert method == "get_devices_activity"
    assert payload["domains"] == ["evil.ru"]


# --- отбор опасных категорий ---------------------------------------------

def test_dangerous_ids_taken_from_api_flags():
    cats = [Category(3, "Malware", True), Category(49, "Internet", False)]
    assert skydns_client.dangerous_ids(cats) == {3}


def test_dangerous_ids_fall_back_to_manual_list():
    """Если API не пометил ни одной категории — берём перечень из инструкции."""
    cats = [Category(49, "Internet", False)]
    assert skydns_client.dangerous_ids(cats) == set(
        skydns_client.DANGEROUS_CATEGORY_IDS
    )
    assert skydns_client.dangerous_ids([]) == set(
        skydns_client.DANGEROUS_CATEGORY_IDS
    )


def test_describe_categories_prefers_dangerous_one():
    catalogue = {
        49: Category(49, "Computers & Internet", False),
        3: Category(3, "Malware", True),
    }
    primary, titles = skydns_client.describe_categories([49, 3], catalogue)
    assert primary == "3"
    assert titles == "Computers & Internet, Malware"


def test_describe_categories_uses_builtin_names_when_catalogue_empty():
    primary, titles = skydns_client.describe_categories([12], {})
    assert primary == "12"
    assert titles == "Botnets & C2"


# --- нормализация домена --------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("Evil.RU", "evil.ru"),
    ("https://bad.ru/path?a=1", "bad.ru"),
    ("*.bad.ru:8080", "bad.ru"),
    ("bad.ru.", "bad.ru"),
    ("localhost", ""),
    ("", ""),
])
def test_clean_domain(raw, expected):
    assert skydns_client._clean_domain(raw) == expected


# --- импорт CSV -----------------------------------------------------------

def test_parse_csv_semicolon_and_bom():
    data = "﻿domain;category;requests\r\nbad.ru;malware;42\r\n".encode("utf-8")
    stats = skydns_client.parse_csv(data)
    assert stats[0].domain == "bad.ru"
    assert stats[0].requests == 42
    assert stats[0].category == "malware"


def test_parse_csv_cp1251_russian_headers():
    data = "Домен;Категория;Запросы\r\nbad.ru;Вредоносное ПО;3\r\n".encode("cp1251")
    stats = skydns_client.parse_csv(data)
    assert stats[0].domain == "bad.ru"
    assert stats[0].category == "Вредоносное ПО"


def test_parse_csv_without_domain_column_is_rejected():
    with pytest.raises(SkydnsError):
        skydns_client.parse_csv(b"foo;bar\r\n1;2\r\n")


# --- разбор ошибок --------------------------------------------------------

def test_non_json_response_is_reported(monkeypatch):
    client = SkydnsClient(SkydnsConfig(user_id="1", token="t"))

    class FakeResponse:
        def read(self):
            return b"<html>login</html>"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(client._opener, "open", lambda *a, **k: FakeResponse())
    with pytest.raises(SkydnsError, match="не JSON"):
        client._call("get_activity", {})


def test_json_body_is_sent_as_post(monkeypatch):
    client = SkydnsClient(SkydnsConfig(user_id="1", token="secret"))
    seen = {}

    class FakeResponse:
        def read(self):
            return b"[]"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_open(request, timeout=None):
        seen["url"] = request.full_url
        seen["body"] = json.loads(request.data.decode())
        seen["auth"] = request.get_header("Authorization")
        return FakeResponse()

    monkeypatch.setattr(client._opener, "open", fake_open)
    client._call("get_domains_activity", {"period": "date"})

    assert seen["auth"] == "Token secret"
    assert seen["body"] == {"period": "date"}
    assert seen["url"].endswith("/proxy/v2/get_domains_activity/")


# --- асинхронный отчёт и диагностика --------------------------------------

def _polling_client(monkeypatch, responses):
    """Клиент, отдающий заготовленные ответы по одному на запрос."""
    config = SkydnsConfig(user_id="1", token="t", report_timeout=5)
    client = SkydnsClient(config)
    queue = list(responses)
    # Последний ответ повторяется: так проверяется поведение при затянувшемся
    # формировании отчёта, не завися от числа попыток.
    monkeypatch.setattr(
        client, "_call",
        lambda m, p: queue.pop(0) if len(queue) > 1 else queue[0],
    )
    monkeypatch.setattr(skydns_client.time, "sleep", lambda _s: None)
    return client


def test_report_waits_until_ready(monkeypatch):
    """Пока отчёт строится, приходит статус — запрос повторяется."""
    client = _polling_client(monkeypatch, [
        {"status": "pending"},
        {"status": "in_progress"},
        [{"cat": {"id": 3, "title": "Malware", "is_dangerous": True}}],
    ])
    cats = client.categories(START, END)
    assert [c.id for c in cats] == [3]


def test_report_unwraps_envelope(monkeypatch):
    """Отчёт может лежать внутри конверта — достаём его оттуда."""
    client = _polling_client(monkeypatch, [
        {"status": "ready", "result": [
            {"domain": "evil.ru", "requests": 5, "cat_ids": [3]},
        ]},
    ])
    stats = client.domains(START, END)
    assert [s.domain for s in stats] == ["evil.ru"]


def test_report_unwraps_data_key_without_status(monkeypatch):
    client = _polling_client(monkeypatch, [
        {"data": [{"domain": "evil.ru"}]},
    ])
    assert [s.domain for s in client.domains(START, END)] == ["evil.ru"]


def test_report_gives_up_with_the_last_response(monkeypatch):
    """Не дождались — в ошибке видно, что именно отвечал сервер."""
    client = _polling_client(monkeypatch, [{"status": "pending"}])
    with pytest.raises(SkydnsError) as exc:
        client.categories(START, END)
    assert "pending" in str(exc.value)
    assert "get_categories_activity" in str(exc.value)


def test_failed_status_is_reported_with_detail(monkeypatch):
    client = _polling_client(monkeypatch, [
        {"status": "error", "detail": "период слишком большой"},
    ])
    with pytest.raises(SkydnsError, match="период слишком большой"):
        client.categories(START, END)


def test_error_body_without_status_is_reported(monkeypatch):
    """Ответ вида {"detail": "..."} — это ошибка, а не отчёт."""
    client = _polling_client(monkeypatch, [
        {"detail": "Authentication credentials were not provided."},
    ])
    with pytest.raises(SkydnsError, match="Authentication credentials"):
        client.categories(START, END)


def test_unexpected_response_shows_what_came_back(monkeypatch):
    """Главное свойство: в ошибке виден реальный ответ, а не общая фраза."""
    client = _polling_client(monkeypatch, [12345])
    with pytest.raises(SkydnsError) as exc:
        client.categories(START, END)
    message = str(exc.value)
    assert "12345" in message
    assert "get_categories_activity" in message


def test_total_activity_accepts_plain_dict(monkeypatch):
    """У сводки ответ — объект, и это не конверт статуса."""
    client = _polling_client(monkeypatch, [
        {"requests": 10, "blocks": 2, "dangerous_requests": 1},
    ])
    assert client.total_activity(START, END)["requests"] == 10


def test_total_activity_waits_for_envelope(monkeypatch):
    client = _polling_client(monkeypatch, [
        {"status": "processing"},
        {"status": "done", "result": {"requests": 7, "blocks": 1}},
    ])
    assert client.total_activity(START, END)["requests"] == 7


def test_probe_returns_raw_response(monkeypatch):
    """Диагностика отдаёт ответ как есть, без разбора."""
    client = _polling_client(monkeypatch, [{"status": "pending"}])
    result = client.probe("get_categories_activity", START, END)
    assert result["response"] == {"status": "pending"}
    assert result["url"].endswith("/proxy/v2/get_categories_activity/")
    assert result["request"]["period"] == "range"


# --- реальный протокол: конверт задачи + файл отчёта ----------------------

REAL_ENVELOPE = {
    "task_id": "e31877f316ea25cf0c1cf0835ede0427",
    "status": "exists: complete",
    "message": "https://stch.skydns.ru/data/26a8536a3b42.json",
    "updated": "2026-08-10 18:05:33",
    "processing_time": 3.3166539999999993,
}


def _client_with_file(monkeypatch, envelope, report, capture=None):
    """Клиент, у которого метод отдаёт конверт, а ссылка — файл отчёта."""
    client = SkydnsClient(SkydnsConfig(user_id="1", token="t", report_timeout=5))
    monkeypatch.setattr(client, "_call", lambda m, p: envelope)

    def fake_fetch(url):
        if capture is not None:
            capture.append(url)
        return report

    monkeypatch.setattr(client, "_fetch_report", fake_fetch)
    monkeypatch.setattr(skydns_client.time, "sleep", lambda _s: None)
    return client


def test_cached_report_status_is_recognised(monkeypatch):
    """«exists: complete» — это готовый отчёт из кэша, а не «ещё не готово»."""
    urls = []
    client = _client_with_file(
        monkeypatch, REAL_ENVELOPE,
        [{"cat": {"id": 3, "title": "Malware", "is_dangerous": True}}],
        capture=urls,
    )
    cats = client.categories(START, END)
    assert [c.id for c in cats] == [3]
    # Отчёт скачан именно по ссылке из конверта.
    assert urls == ["https://stch.skydns.ru/data/26a8536a3b42.json"]


def test_plain_complete_status_also_works(monkeypatch):
    envelope = dict(REAL_ENVELOPE, status="complete")
    client = _client_with_file(monkeypatch, envelope,
                               [{"domain": "evil.ru", "requests": 5}])
    assert [s.domain for s in client.domains(START, END)] == ["evil.ru"]


def test_status_with_error_prefix_is_an_error(monkeypatch):
    client = _client_with_file(
        monkeypatch,
        {"task_id": "x", "status": "error: period too large", "message": ""},
        [],
    )
    with pytest.raises(SkydnsError, match="period too large"):
        client.categories(START, END)


def test_ready_without_link_or_data_is_reported(monkeypatch):
    """Готово, но ни ссылки, ни данных — молча притворяться нечем."""
    client = _client_with_file(
        monkeypatch, {"task_id": "x", "status": "complete"}, [],
    )
    with pytest.raises(SkydnsError, match="ни ссылки, ни данных"):
        client.categories(START, END)


def test_pending_then_complete_downloads_the_file(monkeypatch):
    """Первый ответ — «в работе», второй — готовый отчёт со ссылкой."""
    client = SkydnsClient(SkydnsConfig(user_id="1", token="t", report_timeout=5))
    envelopes = [
        {"task_id": "x", "status": "new"},
        {"task_id": "x", "status": "in progress"},
        REAL_ENVELOPE,
    ]
    monkeypatch.setattr(
        client, "_call",
        lambda m, p: envelopes.pop(0) if len(envelopes) > 1 else envelopes[0],
    )
    monkeypatch.setattr(client, "_fetch_report",
                        lambda url: [{"domain": "evil.ru"}])
    monkeypatch.setattr(skydns_client.time, "sleep", lambda _s: None)

    assert [s.domain for s in client.domains(START, END)] == ["evil.ru"]


def test_report_file_may_be_wrapped(monkeypatch):
    """Файл отчёта тоже может быть обёрнут — достаём список изнутри."""
    client = _client_with_file(monkeypatch, REAL_ENVELOPE,
                               {"result": [{"domain": "evil.ru"}]})
    assert [s.domain for s in client.domains(START, END)] == ["evil.ru"]


def test_wrong_report_file_shape_names_the_source(monkeypatch):
    client = _client_with_file(monkeypatch, REAL_ENVELOPE, {"oops": 1})
    with pytest.raises(SkydnsError) as exc:
        client.domains(START, END)
    assert "stch.skydns.ru" in str(exc.value)


def test_total_activity_reads_object_from_the_file(monkeypatch):
    client = _client_with_file(monkeypatch, REAL_ENVELOPE,
                               {"requests": 39352, "blocks": 0,
                                "dangerous_requests": 39352})
    assert client.total_activity(START, END)["requests"] == 39352
