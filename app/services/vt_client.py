"""Проверка индикаторов в VirusTotal (API v3).

Используется только стандартная библиотека, чтобы не тянуть лишних зависимостей.
Ключ API хранится в настройках приложения в зашифрованном виде.

Ограничения бесплатного ключа: 4 запроса в минуту, 500 в сутки — поэтому
массовая проверка идёт небольшими пакетами и корректно обрабатывает ответ 429.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

API_DOMAIN = "https://www.virustotal.com/api/v3/domains/{}"
API_IP = "https://www.virustotal.com/api/v3/ip_addresses/{}"
GUI_DOMAIN = "https://www.virustotal.com/gui/domain/{}"
GUI_IP = "https://www.virustotal.com/gui/ip-address/{}"


class VtError(Exception):
    """Ошибка обращения к VirusTotal, пригодная для показа оператору."""


class VtRateLimit(VtError):
    """Превышен лимит запросов — массовую проверку следует остановить."""


@dataclass
class VtResult:
    value: str
    kind: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    reputation: int = 0
    permalink: str = ""

    @property
    def total_engines(self) -> int:
        return (self.malicious + self.suspicious + self.harmless
                + self.undetected + self.timeout)


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def check(value: str, api_key: str, timeout: int = 20) -> VtResult:
    """Запросить вердикт по домену или IP. Бросает VtError при неудаче."""
    value = (value or "").strip().lower()
    if not value:
        raise VtError("Пустое значение для проверки.")
    if not api_key:
        raise VtError(
            "Не задан ключ API VirusTotal — укажите его в разделе «Настройки»."
        )

    kind = "ip" if _is_ip(value) else "domain"
    url = (API_IP if kind == "ip" else API_DOMAIN).format(value)
    request = urllib.request.Request(url, headers={
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "rpz-fstec/1.0",
    })

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise VtError("VirusTotal отклонил ключ API (401). Проверьте ключ.") from exc
        if exc.code == 429:
            raise VtRateLimit(
                "Превышен лимит запросов VirusTotal (429). "
                "У бесплатного ключа — 4 запроса в минуту и 500 в сутки."
            ) from exc
        if exc.code == 404:
            raise VtError(f"VirusTotal не знает объект {value} (404).") from exc
        raise VtError(f"VirusTotal вернул ошибку {exc.code}.") from exc
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        raise VtError(f"Не удалось связаться с VirusTotal: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise VtError("VirusTotal вернул некорректный ответ.") from exc

    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return VtResult(
        value=value,
        kind=kind,
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        timeout=int(stats.get("timeout", 0) or 0),
        reputation=int(attributes.get("reputation", 0) or 0),
        permalink=(GUI_IP if kind == "ip" else GUI_DOMAIN).format(value),
    )
