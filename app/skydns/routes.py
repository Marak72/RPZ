"""Сервис «Угрозы SkyDNS».

Цепочка работы оператора:

  1. Из SkyDNS приезжает статистика обращений по доменам (API или CSV-выгрузка).
  2. Остаются только домены категорий, связанных с безопасностью.
  3. По каждому домену делается запрос в MaxPatrol SIEM с группировкой по
     ``dst.host`` — так находятся конечные хосты организации, которые туда ходили.
  4. Разобранный домен можно одним действием отправить в блокировку RPZ —
     он попадает в кандидаты сервиса «РПЗ ФСТЭК» и выгружается на DNS-сервер.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func

from ..extensions import db
from ..models import (
    JOB_FAILED,
    JOB_SUCCESS,
    STATUS_NEW,
    THREAT_BLOCKED,
    THREAT_NEW,
    THREAT_SOURCE_API,
    THREAT_SOURCE_CSV,
    THREAT_SOURCE_MANUAL,
    THREAT_STATUSES,
    BlockEntry,
    SiemQueryLog,
    SkydnsSyncLog,
    ThreatDomain,
    ThreatHost,
)
from ..services import skydns_client
from ..services.siem_client import SiemClient, SiemError
from ..services.skydns_client import SkydnsClient, SkydnsError
from ..settings_store import (
    KEY_SIEM_URL,
    KEY_SIEM_WINDOW,
    KEY_SKYDNS_DAYS,
    get_int,
    get_setting,
    get_siem_filter_template,
    get_siem_group_field,
    get_skydns_categories,
    load_siem_config,
    load_skydns_config,
)
from ..web_utils import csv_response, fmt_dt, operator_required
from .forms import ImportForm, ManualThreatForm, SyncForm, ThreatNotesForm

skydns_bp = Blueprint("skydns", __name__, url_prefix="/skydns")

PER_PAGE = 100
DEFAULT_WINDOW_HOURS = 24 * 7
DEFAULT_SYNC_DAYS = 7
# Сколько доменов разрешаем обработать за один пакетный запрос в SIEM:
# каждый домен — отдельный запрос, длинная пачка упрётся в таймаут веб-сервера.
BATCH_LIMIT = 25


def _back_url(default_endpoint: str = "skydns.domains") -> str:
    """Вернуться на страницу, с которой пришли, но только внутри портала.

    Referrer приходит от браузера, поэтому чужой хост в нём игнорируется —
    иначе получился бы открытый редирект наружу.
    """
    referrer = request.referrer or ""
    if referrer:
        host = urlsplit(referrer).netloc
        if not host or host == urlsplit(request.host_url).netloc:
            return referrer
    return url_for(default_endpoint)


@skydns_bp.app_context_processor
def inject_skydns_counts():
    """Счётчики для боковой навигации сервиса."""
    empty = {"threats": 0, "new": 0, "hosts": 0, "blocked": 0}
    if not current_user.is_authenticated:
        return {"skydns_counts": empty}
    try:
        return {
            "skydns_counts": {
                "threats": ThreatDomain.query.count(),
                "new": ThreatDomain.query.filter_by(status=THREAT_NEW).count(),
                "hosts": db.session.query(
                    func.count(func.distinct(ThreatHost.address))
                ).scalar() or 0,
                "blocked": ThreatDomain.query.filter_by(
                    status=THREAT_BLOCKED
                ).count(),
            }
        }
    except Exception:  # noqa: BLE001 — например, БД ещё не мигрирована
        current_app.logger.exception("Не удалось посчитать счётчики SkyDNS")
        return {"skydns_counts": empty}


# --- Дашборд --------------------------------------------------------------

@skydns_bp.route("/")
@login_required
def dashboard():
    threats = ThreatDomain.query
    hosts_total = db.session.query(
        func.count(func.distinct(ThreatHost.address))
    ).scalar() or 0

    stats = {
        "threats": threats.count(),
        "new": threats.filter_by(status=THREAT_NEW).count(),
        "blocked": threats.filter_by(status=THREAT_BLOCKED).count(),
        "hosts": hosts_total,
        "unchecked": threats.filter(ThreatDomain.siem_checked_at.is_(None)).count(),
    }

    # Топ категорий и топ хостов — с них обычно начинают разбор.
    top_categories = (
        db.session.query(
            ThreatDomain.category, func.count(ThreatDomain.id).label("cnt")
        )
        .group_by(ThreatDomain.category)
        .order_by(func.count(ThreatDomain.id).desc())
        .limit(8)
        .all()
    )
    top_hosts = (
        db.session.query(
            ThreatHost.address,
            func.count(func.distinct(ThreatHost.threat_id)).label("domains"),
            func.sum(ThreatHost.events_count).label("events"),
        )
        .group_by(ThreatHost.address)
        .order_by(func.count(func.distinct(ThreatHost.threat_id)).desc())
        .limit(8)
        .all()
    )
    recent_threats = (
        ThreatDomain.query.order_by(ThreatDomain.last_seen.desc()).limit(8).all()
    )
    recent_syncs = (
        SkydnsSyncLog.query.order_by(SkydnsSyncLog.started_at.desc()).limit(5).all()
    )

    return render_template(
        "skydns/dashboard.html",
        stats=stats,
        top_categories=top_categories,
        top_hosts=top_hosts,
        recent_threats=recent_threats,
        recent_syncs=recent_syncs,
        siem_configured=bool(get_setting(KEY_SIEM_URL)),
    )


# --- Домены ---------------------------------------------------------------

def _threats_query():
    query = ThreatDomain.query
    search = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "").strip()
    category = (request.args.get("category") or "").strip()

    if search:
        query = query.filter(ThreatDomain.domain.ilike(f"%{search}%"))
    if status:
        query = query.filter(ThreatDomain.status == status)
    if category:
        query = query.filter(ThreatDomain.category == category)
    return query


@skydns_bp.route("/domains")
@login_required
def domains():
    page = request.args.get("page", 1, type=int)
    pagination = (
        _threats_query()
        .order_by(ThreatDomain.last_seen.desc(), ThreatDomain.domain)
        .paginate(page=page, per_page=PER_PAGE, error_out=False)
    )
    categories = [
        row[0] for row in
        db.session.query(ThreatDomain.category)
        .filter(ThreatDomain.category != "")
        .distinct()
        .order_by(ThreatDomain.category)
        .all()
    ]
    return render_template(
        "skydns/domains.html",
        items=pagination.items,
        pagination=pagination,
        categories=categories,
        statuses=THREAT_STATUSES,
        q=request.args.get("q", ""),
        status=request.args.get("status", ""),
        category=request.args.get("category", ""),
    )


@skydns_bp.route("/domains.csv")
@login_required
def domains_csv():
    rows = (
        _threats_query().order_by(ThreatDomain.last_seen.desc()).all()
    )
    return csv_response(
        "skydns-threats",
        ["Домен", "Категория", "Статус", "Обращений", "Блокировок",
         "Хостов", "Первый раз", "Последний раз", "Проверка в SIEM"],
        [
            [
                item.domain,
                item.category_title or item.category,
                item.status_title,
                item.requests_count,
                item.blocks_count,
                item.siem_hosts_count,
                fmt_dt(item.first_seen),
                fmt_dt(item.last_seen),
                fmt_dt(item.siem_checked_at),
            ]
            for item in rows
        ],
    )


@skydns_bp.route("/domains/<int:threat_id>", methods=["GET", "POST"])
@login_required
def threat_view(threat_id: int):
    threat = db.get_or_404(ThreatDomain, threat_id)
    form = ThreatNotesForm(status=threat.status, notes=threat.notes)
    form.status.choices = list(THREAT_STATUSES)

    if form.submit_notes.data and form.validate_on_submit():
        if not current_user.is_operator:
            flash("Изменение доступно только операторам.", "danger")
            return redirect(url_for("skydns.threat_view", threat_id=threat.id))
        threat.status = form.status.data
        threat.notes = form.notes.data or ""
        db.session.commit()
        flash("Сохранено.", "success")
        return redirect(url_for("skydns.threat_view", threat_id=threat.id))

    hosts = (
        threat.hosts.order_by(ThreatHost.events_count.desc(), ThreatHost.address).all()
    )
    lookups = (
        SiemQueryLog.query.filter_by(threat_id=threat.id)
        .order_by(SiemQueryLog.started_at.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "skydns/threat.html",
        threat=threat,
        hosts=hosts,
        lookups=lookups,
        form=form,
        window_hours=get_int(KEY_SIEM_WINDOW, DEFAULT_WINDOW_HOURS),
        siem_configured=bool(get_setting(KEY_SIEM_URL)),
    )


@skydns_bp.route("/domains/<int:threat_id>/delete", methods=["POST"])
@operator_required
def threat_delete(threat_id: int):
    threat = db.get_or_404(ThreatDomain, threat_id)
    domain = threat.domain
    SiemQueryLog.query.filter_by(threat_id=threat.id).update({"threat_id": None})
    db.session.delete(threat)
    db.session.commit()
    flash(f"Домен {domain} удалён из разбора.", "success")
    return redirect(url_for("skydns.domains"))


# --- Поиск конечных хостов в MaxPatrol SIEM -------------------------------

def _window() -> tuple[datetime, datetime]:
    hours = get_int(KEY_SIEM_WINDOW, DEFAULT_WINDOW_HOURS)
    time_to = datetime.now()
    return time_to - timedelta(hours=max(hours, 1)), time_to


def _apply_hits(threat: ThreatDomain, hits) -> int:
    """Сохранить найденные хосты, не теряя результаты прошлых проверок."""
    existing = {host.address: host for host in threat.hosts}
    now = datetime.utcnow()
    for hit in hits:
        host = existing.get(hit.address)
        if host is None:
            host = ThreatHost(
                threat_id=threat.id,
                address=hit.address,
                hostname=hit.hostname or "",
                first_seen=hit.first_seen or now,
                # Значение по умолчанию появится только при вставке,
                # а счётчик сравнивается прямо сейчас.
                events_count=0,
            )
            db.session.add(host)
            existing[hit.address] = host
        host.events_count = max(host.events_count or 0, hit.events_count)
        host.last_seen = hit.last_seen or now
        host.found_at = now
        if hit.hostname:
            host.hostname = hit.hostname
    return len(existing)


def _lookup(threats: list[ThreatDomain]) -> tuple[int, int, list[str]]:
    """Найти в SIEM конечные хосты для списка доменов.

    Вход в SIEM выполняется один раз на всю пачку. Возвращает количество
    успешно обработанных доменов, количество ошибок и список сообщений.
    """
    config = load_siem_config()
    filter_template = get_siem_filter_template()
    group_field = get_siem_group_field()
    time_from, time_to = _window()

    done = failed = 0
    messages: list[str] = []

    client = SiemClient(config)
    try:
        client.login()
    except SiemError as exc:
        client.close()
        for threat in threats:
            db.session.add(SiemQueryLog(
                threat_id=threat.id, domain=threat.domain, status=JOB_FAILED,
                finished_at=datetime.utcnow(), message=str(exc),
                period_from=time_from, period_to=time_to,
                user_id=current_user.id,
            ))
        db.session.commit()
        return 0, len(threats), [str(exc)]

    try:
        for threat in threats:
            log = SiemQueryLog(
                threat_id=threat.id,
                domain=threat.domain,
                period_from=time_from,
                period_to=time_to,
                user_id=current_user.id,
            )
            db.session.add(log)
            try:
                result = client.search_hosts(
                    threat.domain, time_from, time_to,
                    filter_template, group_field,
                )
            except SiemError as exc:
                log.status = JOB_FAILED
                log.finished_at = datetime.utcnow()
                log.message = str(exc)
                failed += 1
                messages.append(f"{threat.domain}: {exc}")
                continue

            db.session.flush()  # закрепить журнальную запись до вставки хостов
            total_hosts = _apply_hits(threat, result.hosts)
            threat.siem_checked_at = datetime.utcnow()
            threat.siem_hosts_count = total_hosts

            log.status = JOB_SUCCESS
            log.finished_at = datetime.utcnow()
            log.hosts_found = len(result.hosts)
            log.events_total = result.total_count
            log.query_filter = result.query_filter
            log.message = (
                f"Найдено хостов: {len(result.hosts)}; "
                f"событий: {result.total_count}."
            )
            done += 1
    finally:
        client.close()
        db.session.commit()

    return done, failed, messages


@skydns_bp.route("/domains/<int:threat_id>/lookup", methods=["POST"])
@operator_required
def threat_lookup(threat_id: int):
    threat = db.get_or_404(ThreatDomain, threat_id)
    done, failed, messages = _lookup([threat])
    if done:
        flash(
            f"SIEM: найдено хостов — {threat.siem_hosts_count}.",
            "success" if threat.siem_hosts_count else "info",
        )
    if failed:
        flash("\n".join(messages) or "Запрос в SIEM не удался.", "danger")
    return redirect(url_for("skydns.threat_view", threat_id=threat.id))


@skydns_bp.route("/lookup-batch", methods=["POST"])
@operator_required
def lookup_batch():
    """Проверить в SIEM выбранные домены (или ещё ни разу не проверенные)."""
    ids = request.form.getlist("threat_id", type=int)
    if ids:
        threats = ThreatDomain.query.filter(ThreatDomain.id.in_(ids)).all()
    else:
        threats = (
            ThreatDomain.query
            .filter(ThreatDomain.siem_checked_at.is_(None))
            .order_by(ThreatDomain.last_seen.desc())
            .limit(BATCH_LIMIT)
            .all()
        )

    if not threats:
        flash("Нет доменов для проверки в SIEM.", "info")
        return redirect(_back_url())

    if len(threats) > BATCH_LIMIT:
        threats = threats[:BATCH_LIMIT]
        flash(
            f"За один раз обрабатывается не больше {BATCH_LIMIT} доменов — "
            "запустите проверку ещё раз для остальных.",
            "info",
        )

    done, failed, messages = _lookup(threats)
    if done:
        flash(f"Проверено доменов: {done}.", "success")
    if failed:
        preview = "\n".join(messages[:5])
        flash(f"Не удалось проверить доменов: {failed}.\n{preview}", "danger")
    return redirect(_back_url())


# --- Конечные хосты -------------------------------------------------------

def _hosts_rows():
    query = (
        db.session.query(
            ThreatHost.address,
            func.count(func.distinct(ThreatHost.threat_id)).label("domains"),
            func.sum(ThreatHost.events_count).label("events"),
            func.max(ThreatHost.found_at).label("last_found"),
        )
        .group_by(ThreatHost.address)
    )
    search = (request.args.get("q") or "").strip()
    if search:
        query = query.filter(ThreatHost.address.ilike(f"%{search}%"))
    return query.order_by(
        func.count(func.distinct(ThreatHost.threat_id)).desc(),
        ThreatHost.address,
    )


@skydns_bp.route("/hosts")
@login_required
def hosts():
    page = request.args.get("page", 1, type=int)
    pagination = _hosts_rows().paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )
    return render_template(
        "skydns/hosts.html",
        items=pagination.items,
        pagination=pagination,
        q=request.args.get("q", ""),
    )


@skydns_bp.route("/hosts.csv")
@login_required
def hosts_csv():
    rows = _hosts_rows().all()
    return csv_response(
        "skydns-hosts",
        ["Хост", "Вредоносных доменов", "Событий", "Последняя проверка"],
        [[row.address, row.domains, row.events or 0, fmt_dt(row.last_found)]
         for row in rows],
    )


@skydns_bp.route("/host")
@login_required
def host_view():
    """Карточка конечного хоста: куда именно он ходил."""
    address = (request.args.get("address") or "").strip()
    if not address:
        return redirect(url_for("skydns.hosts"))

    rows = (
        db.session.query(ThreatHost, ThreatDomain)
        .join(ThreatDomain, ThreatHost.threat_id == ThreatDomain.id)
        .filter(ThreatHost.address == address)
        .order_by(ThreatHost.events_count.desc())
        .all()
    )
    total_events = sum(host.events_count for host, _ in rows)
    return render_template(
        "skydns/host.html",
        address=address,
        rows=rows,
        total_events=total_events,
    )


# --- Загрузка статистики --------------------------------------------------

def _upsert_stats(stats, source: str) -> tuple[int, int]:
    """Сохранить статистику, оставив только категории безопасности."""
    allowed = get_skydns_categories()
    now = datetime.utcnow()
    total = new = 0

    for stat in stats:
        if source != THREAT_SOURCE_MANUAL and not skydns_client.is_security_category(
            stat.category, stat.category_title, allowed
        ):
            continue
        total += 1
        threat = ThreatDomain.query.filter_by(domain=stat.domain).first()
        if threat is None:
            threat = ThreatDomain(
                domain=stat.domain,
                first_seen=now,
                source=source,
                added_by=current_user.id,
                # Значения по умолчанию проставляются только при вставке,
                # а счётчики нужны прямо сейчас — ниже идёт сравнение.
                requests_count=0,
                blocks_count=0,
            )
            db.session.add(threat)
            new += 1
        threat.last_seen = now
        # Счётчики приходят за период выборки — берём максимум, а не затираем.
        threat.requests_count = max(threat.requests_count or 0, stat.requests)
        threat.blocks_count = max(threat.blocks_count or 0, stat.blocks)
        if stat.category:
            threat.category = stat.category
        if stat.category_title:
            threat.category_title = stat.category_title
        if stat.profile:
            threat.profile = stat.profile

    db.session.commit()
    return total, new


@skydns_bp.route("/sync", methods=["GET", "POST"])
@login_required
def sync():
    sync_form = SyncForm()
    import_form = ImportForm()
    manual_form = ManualThreatForm()

    days = get_int(KEY_SKYDNS_DAYS, DEFAULT_SYNC_DAYS)
    if not sync_form.start.data:
        sync_form.start.data = date.today() - timedelta(days=days)
    if not sync_form.end.data:
        sync_form.end.data = date.today()

    if request.method == "POST" and not current_user.is_operator:
        flash("Загрузка статистики доступна только операторам.", "danger")
        return redirect(url_for("skydns.sync"))

    if sync_form.submit_sync.data and sync_form.validate_on_submit():
        return _do_api_sync(sync_form)

    if import_form.submit_import.data and import_form.validate_on_submit():
        return _do_csv_import(import_form)

    if manual_form.submit_manual.data and manual_form.validate_on_submit():
        return _do_manual_add(manual_form)

    return render_template(
        "skydns/sync.html",
        sync_form=sync_form,
        import_form=import_form,
        manual_form=manual_form,
        categories=get_skydns_categories(),
        skydns_configured=load_skydns_config().is_configured,
        recent=SkydnsSyncLog.query.order_by(
            SkydnsSyncLog.started_at.desc()
        ).limit(10).all(),
    )


def _do_api_sync(form):
    start = form.start.data or date.today() - timedelta(days=DEFAULT_SYNC_DAYS)
    end = form.end.data or date.today()
    if start > end:
        flash("Начало периода позже его конца.", "danger")
        return redirect(url_for("skydns.sync"))

    log = SkydnsSyncLog(
        source=THREAT_SOURCE_API,
        period_from=start,
        period_to=end,
        user_id=current_user.id,
    )
    db.session.add(log)

    try:
        stats = SkydnsClient(load_skydns_config()).fetch_domains(start, end)
    except SkydnsError as exc:
        log.status = JOB_FAILED
        log.finished_at = datetime.utcnow()
        log.message = str(exc)
        db.session.commit()
        flash(str(exc), "danger")
        return redirect(url_for("skydns.sync"))
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Ошибка выгрузки из SkyDNS")
        log.status = JOB_FAILED
        log.finished_at = datetime.utcnow()
        log.message = f"Непредвиденная ошибка: {exc}"
        db.session.commit()
        flash(f"Непредвиденная ошибка выгрузки: {exc}", "danger")
        return redirect(url_for("skydns.sync"))

    total, new = _upsert_stats(stats, THREAT_SOURCE_API)
    log.status = JOB_SUCCESS
    log.finished_at = datetime.utcnow()
    log.domains_total = total
    log.domains_new = new
    log.message = (
        f"Строк в ответе: {len(stats)}; относятся к безопасности: {total}; "
        f"новых: {new}."
    )
    db.session.commit()
    flash(
        f"Из SkyDNS получено строк: {len(stats)}. "
        f"Опасных доменов: {total}, из них новых: {new}.",
        "success",
    )
    return redirect(url_for("skydns.domains"))


def _do_csv_import(form):
    log = SkydnsSyncLog(source=THREAT_SOURCE_CSV, user_id=current_user.id)
    db.session.add(log)

    data = form.report.data.read()
    try:
        stats = skydns_client.parse_csv(data, load_skydns_config().field_map)
    except SkydnsError as exc:
        log.status = JOB_FAILED
        log.finished_at = datetime.utcnow()
        log.message = str(exc)
        db.session.commit()
        flash(str(exc), "danger")
        return redirect(url_for("skydns.sync"))

    total, new = _upsert_stats(stats, THREAT_SOURCE_CSV)
    log.status = JOB_SUCCESS
    log.finished_at = datetime.utcnow()
    log.domains_total = total
    log.domains_new = new
    log.message = (
        f"Строк в файле: {len(stats)}; относятся к безопасности: {total}; "
        f"новых: {new}."
    )
    db.session.commit()
    flash(
        f"Из файла разобрано строк: {len(stats)}. "
        f"Опасных доменов: {total}, из них новых: {new}.",
        "success",
    )
    return redirect(url_for("skydns.domains"))


def _do_manual_add(form):
    raw = [line.strip().lower() for line in (form.values.data or "").splitlines()]
    stats = [
        skydns_client.DomainStat(
            domain=line.strip(".").lstrip("*."),
            category=(form.category.data or "manual").strip(),
        )
        for line in raw
        if line and "." in line and not line.startswith("#")
    ]
    if not stats:
        flash("Не найдено ни одного корректного домена.", "danger")
        return redirect(url_for("skydns.sync"))

    total, new = _upsert_stats(stats, THREAT_SOURCE_MANUAL)
    flash(f"Добавлено доменов: {total}, из них новых: {new}.", "success")
    return redirect(url_for("skydns.domains"))


# --- Передача домена в блокировку RPZ -------------------------------------

@skydns_bp.route("/domains/<int:threat_id>/to-rpz", methods=["POST"])
@operator_required
def threat_to_rpz(threat_id: int):
    """Отправить домен в кандидаты на блокировку сервиса «РПЗ ФСТЭК»."""
    threat = db.get_or_404(ThreatDomain, threat_id)
    entry = BlockEntry.query.filter_by(value=threat.domain).first()

    if entry is None:
        entry = BlockEntry(
            value=threat.domain,
            entry_type="domain",
            status=STATUS_NEW,
            source="skydns",
            added_by=current_user.id,
            notes=(
                f"Из сервиса SkyDNS. Категория: "
                f"{threat.category_title or threat.category or '—'}. "
                f"Конечных хостов найдено: {threat.siem_hosts_count}."
            ),
        )
        db.session.add(entry)
        message = (
            f"{threat.domain} добавлен в кандидаты на блокировку. "
            "Выгрузите его в RPZ в сервисе «РПЗ ФСТЭК»."
        )
    else:
        message = f"{threat.domain} уже есть в кандидатах на блокировку."

    threat.status = THREAT_BLOCKED
    db.session.commit()
    flash(message, "success")
    return redirect(url_for("skydns.threat_view", threat_id=threat.id))


# --- Журналы --------------------------------------------------------------

@skydns_bp.route("/logs")
@login_required
def logs():
    page = request.args.get("page", 1, type=int)
    pagination = (
        SiemQueryLog.query.order_by(SiemQueryLog.started_at.desc())
        .paginate(page=page, per_page=PER_PAGE, error_out=False)
    )
    return render_template(
        "skydns/logs.html",
        items=pagination.items,
        pagination=pagination,
        syncs=SkydnsSyncLog.query.order_by(
            SkydnsSyncLog.started_at.desc()
        ).limit(20).all(),
    )
