"""Сохранение вердиктов VirusTotal — общее для сервисов портала.

Отчёт лежит в одной таблице и не привязан к сервису: домен из письма ФСТЭК
и домен из статистики SkyDNS — это один и тот же домен, и проверять его
дважды незачем. Здесь собрана работа с этой таблицей, чтобы оба сервиса
вызывали одно и то же, а не заводили каждый свою копию логики.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db
from .models import VtReport
from .settings_store import get_vt_key
from . import vt_client


def store(result, error: str = "", value: str = "", kind: str = "domain",
          user_id: int | None = None) -> VtReport:
    """Сохранить (или обновить) отчёт VirusTotal."""
    value = (result.value if result else value).lower()
    report = VtReport.query.filter_by(value=value).first()
    if report is None:
        report = VtReport(value=value)
        db.session.add(report)
    report.kind = result.kind if result else kind
    report.checked_at = datetime.utcnow()
    report.checked_by = user_id
    report.error = error[:500]
    if result:
        report.malicious = result.malicious
        report.suspicious = result.suspicious
        report.harmless = result.harmless
        report.undetected = result.undetected
        report.reputation = result.reputation
        report.total_engines = result.total_engines
        report.permalink = result.permalink
    return report


def check_and_store(value: str, user_id: int | None,
                    timeout: int = 20) -> tuple:
    """Проверить значение и записать результат.

    Возвращает ``(отчёт, сообщение оператору, категория сообщения)``.
    Исключение наружу не выпускается: неудачная проверка — это тоже
    результат, и он должен остаться в базе.
    """
    value = (value or "").strip().lower()
    try:
        result = vt_client.check(value, get_vt_key(), timeout=timeout)
    except vt_client.VtError as exc:
        return store(None, error=str(exc), value=value, user_id=user_id), \
            str(exc), "danger"

    report = store(result, user_id=user_id)
    message = (
        f"VirusTotal: {value} — вредоносных вердиктов {result.malicious} "
        f"из {result.total_engines}."
    )
    return report, message, ("danger" if result.malicious else "success")


def check_many(values: list[str], user_id: int | None,
               timeout: int = 20) -> tuple[int, str]:
    """Проверить пачку значений, остановившись на лимите VirusTotal.

    Упёршись в лимит, продолжать бессмысленно: остаток запросов уйдёт в
    отказы. Возвращает число проверенных и текст предупреждения.
    """
    key = get_vt_key()
    done = 0
    for value in values:
        try:
            store(vt_client.check(value, key, timeout=timeout), user_id=user_id)
            done += 1
        except vt_client.VtRateLimit as exc:
            return done, (
                f"Проверка остановлена: {exc} Продолжите позже — уже "
                f"проверенные домены повторно не запрашиваются."
            )
        except vt_client.VtError as exc:
            store(None, error=str(exc), value=value, user_id=user_id)
    return done, ""
