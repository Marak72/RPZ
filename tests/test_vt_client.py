import json
import urllib.error
import urllib.request

import pytest

from app.services import vt_client
from app.services.vt_client import VtError, VtRateLimit


class FakeResponse:
    def __init__(self, payload):
        self._data = json.dumps(payload).encode()

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _payload(malicious=3, suspicious=1, harmless=60, undetected=10, reputation=-5):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": 0,
                },
                "reputation": reputation,
            }
        }
    }


def test_check_domain_parses_stats(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["key"] = request.get_header("X-apikey")
        return FakeResponse(_payload())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = vt_client.check("Evil.COM", "secret-key")

    assert result.value == "evil.com"
    assert result.kind == "domain"
    assert result.malicious == 3
    assert result.total_engines == 74
    assert "domains/evil.com" in captured["url"]
    assert captured["key"] == "secret-key"
    assert result.permalink.endswith("/gui/domain/evil.com")


def test_check_ip_uses_ip_endpoint(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        return FakeResponse(_payload(malicious=0))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = vt_client.check("8.8.8.8", "k")

    assert result.kind == "ip"
    assert "ip_addresses/8.8.8.8" in captured["url"]
    assert result.malicious == 0


def test_missing_key_is_reported():
    with pytest.raises(VtError, match="ключ"):
        vt_client.check("evil.com", "")


def _raise_http(code):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, code, "err", {}, None)
    return fake_urlopen


def test_rate_limit_raises_dedicated_error(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _raise_http(429))
    with pytest.raises(VtRateLimit):
        vt_client.check("evil.com", "k")


def test_bad_key_reported(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _raise_http(401))
    with pytest.raises(VtError, match="401"):
        vt_client.check("evil.com", "k")


def test_unknown_object_reported(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _raise_http(404))
    with pytest.raises(VtError, match="404"):
        vt_client.check("evil.com", "k")


def test_network_error_reported(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("нет сети")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(VtError, match="Не удалось связаться"):
        vt_client.check("evil.com", "k")
