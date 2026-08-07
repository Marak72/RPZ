"""Главная страница портала: список сервисов с ключевыми показателями.

Живёт в корне приложения (снаружи — `/soc/`), потому что сами сервисы
разведены по своим подпутям: `/fstec/` и `/skydns/`.
"""
from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

from ..extensions import db
from ..models import (
    STATUS_NEW,
    THREAT_NEW,
    BlockEntry,
    Document,
    RpzSnapshot,
    ThreatDomain,
    ThreatHost,
)
from sqlalchemy import func

hub_bp = Blueprint("hub", __name__)


@hub_bp.route("/")
@login_required
def index():
    """Витрина портала. Ошибки БД не должны ронять главную страницу."""
    try:
        snapshot = RpzSnapshot.query.order_by(RpzSnapshot.fetched_at.desc()).first()
        blocked = snapshot.entry_count if snapshot else 0
        pending = BlockEntry.query.filter_by(
            entry_type="domain", status=STATUS_NEW
        ).count()
        fstec = {
            "blocked": blocked,
            "pending": pending,
            "documents": Document.query.count(),
            "updated": snapshot.fetched_at if snapshot else None,
        }
        skydns = {
            "threats": ThreatDomain.query.count(),
            "new": ThreatDomain.query.filter_by(status=THREAT_NEW).count(),
            "hosts": db.session.query(
                func.count(func.distinct(ThreatHost.address))
            ).scalar() or 0,
            "unchecked": ThreatDomain.query.filter(
                ThreatDomain.siem_checked_at.is_(None)
            ).count(),
        }
    except Exception:  # noqa: BLE001 — например, БД ещё не мигрирована
        fstec = {"blocked": 0, "pending": 0, "documents": 0, "updated": None}
        skydns = {"threats": 0, "new": 0, "hosts": 0, "unchecked": 0}

    return render_template("hub.html", fstec=fstec, skydns=skydns)
