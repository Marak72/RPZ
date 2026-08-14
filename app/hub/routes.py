"""Главная страница портала: список сервисов с ключевыми показателями.

Живёт в корне приложения (снаружи — `/soc/`), потому что сами сервисы
разведены по своим подпутям: `/fstec/` и `/skydns/`.
"""
from __future__ import annotations

from datetime import date

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from ..core.extensions import db
from ..services.assets.models import AdComputer, NetworkHost
from ..services.fstec.models import STATUS_NEW, BlockEntry, Letter, RpzSnapshot
from ..services.skydns.models import THREAT_NEW, ThreatDomain, ThreatHost
from ..services.tasks.models import TASK_DONE, Task
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
            "documents": Letter.query.count(),
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
        open_tasks = Task.query.filter(Task.status != TASK_DONE)
        tasks = {
            "open": open_tasks.count(),
            "mine": open_tasks.filter(
                Task.assignee_id == current_user.id
            ).count(),
            "overdue": open_tasks.filter(
                Task.due_date.isnot(None), Task.due_date < date.today()
            ).count(),
        }
        assets = {
            "hosts": NetworkHost.query.count(),
            "computers": AdComputer.query.count(),
            "unlinked": NetworkHost.query.filter(
                NetworkHost.ad_computer_id.is_(None)
            ).count(),
        }
    except Exception:  # noqa: BLE001 — например, БД ещё не мигрирована
        fstec = {"blocked": 0, "pending": 0, "documents": 0, "updated": None}
        skydns = {"threats": 0, "new": 0, "hosts": 0, "unchecked": 0}
        tasks = {"open": 0, "mine": 0, "overdue": 0}
        assets = {"hosts": 0, "computers": 0, "unlinked": 0}

    return render_template("hub.html", fstec=fstec, skydns=skydns, tasks=tasks,
                           assets=assets)
