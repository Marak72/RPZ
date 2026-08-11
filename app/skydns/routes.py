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

import json
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
    HOST_SOURCE_SIEM,
    HOST_SOURCE_SKYDNS,
    JOB_FAILED,
    JOB_KIND_SIEM,
    JOB_KIND_SKYDNS,
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
    SkydnsCategory,
    SkydnsSyncLog,
    ThreatDomain,
    ThreatHost,
)
from ..services import domains as dm
from ..services import skydns_client
from ..services.exclusions import Matcher
from ..services.jobs import JobError, active_job
from ..services.jobs import start as start_job
from ..services.siem_client import SiemClient, SiemError
from ..services.skydns_client import SkydnsClient, SkydnsError
from ..settings_store import (
    DEFAULT_SIEM_FILTER,
    DEFAULT_SIEM_GROUP_FIELD,
    DEFAULT_SIEM_MAX_EVENTS,
    DEFAULT_SIEM_TIMEOUT,
    DEFAULT_SKYDNS_LIMIT,
    DEFAULT_SKYDNS_TZ,
    KEY_SIEM_AUTH_MODE,
    KEY_SIEM_AUTH_TYPE,
    KEY_SIEM_CLIENT_ID,
    KEY_SIEM_CLIENT_SECRET,
    KEY_SIEM_FILTER,
    KEY_SIEM_GROUP_FIELD,
    KEY_SIEM_MAX_EVENTS,
    KEY_SIEM_PASSWORD,
    KEY_SIEM_TIMEOUT,
    KEY_SIEM_URL,
    KEY_SIEM_USERNAME,
    KEY_SIEM_VERIFY,
    KEY_SIEM_WINDOW,
    KEY_SKYDNS_AUTO_DEVICES,
    KEY_SKYDNS_DAYS,
    KEY_SKYDNS_DETAIL_LIMIT,
    KEY_SKYDNS_LIMIT,
    KEY_SKYDNS_PROFILE,
    KEY_SKYDNS_TIMEOUT,
    KEY_SKYDNS_TOKEN,
    KEY_SKYDNS_TZ,
    KEY_SKYDNS_URL,
    KEY_SKYDNS_USER_ID,
    KEY_SKYDNS_VERIFY,
    get_bool,
    get_int,
    get_setting,
    get_siem_filter_template,
    get_siem_group_field,
    load_siem_config,
    load_skydns_config,
    set_setting,
)
from ..web_utils import (
    LazyCounts,
    csv_response,
    fmt_dt,
    operator_required,
    service_guard,
)
from .forms import (
    ImportForm,
    ManualThreatForm,
    SiemProbeForm,
    SiemSettingsForm,
    SkydnsSettingsForm,
    SyncForm,
    ThreatNotesForm,
)

skydns_bp = Blueprint("skydns", __name__, url_prefix="/skydns")
# Сервис виден только тем, кому его выдал администратор.
skydns_bp.before_request(service_guard("skydns"))

PER_PAGE = 100
DEFAULT_WINDOW_HOURS = 24 * 7
DEFAULT_SYNC_DAYS = 1
# Сколько доменов разрешаем обработать за один пакетный поиск в SIEM.
# Раньше предел был 25: поиск шёл прямо в обработчике запроса и длинная пачка
# упиралась в таймаут веб-сервера. Теперь работа идёт в фоне, и ограничение
# нужно только чтобы одно задание не растянулось на полдня.
BATCH_LIMIT = 200
# Сколько строк детализации забираем за одну выгрузку: из них строится
# соответствие «домен → устройство».
DEFAULT_DETAIL_LIMIT = 5000

# Методы, доступные в диагностике настроек.
PROBE_METHODS = (
    skydns_client.M_TOTAL,
    skydns_client.M_CATEGORIES,
    skydns_client.M_DOMAINS,
    skydns_client.M_DEVICES,
    skydns_client.M_ACTIVITY,
)


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


SKYDNS_COUNTS_EMPTY = {"threats": 0, "new": 0, "hosts": 0, "blocked": 0}


def _skydns_counts() -> dict:
    return {
        "threats": ThreatDomain.query.count(),
        "new": ThreatDomain.query.filter_by(status=THREAT_NEW).count(),
        "hosts": db.session.query(
            func.count(func.distinct(ThreatHost.address))
        ).scalar() or 0,
        "blocked": ThreatDomain.query.filter_by(status=THREAT_BLOCKED).count(),
    }


@skydns_bp.app_context_processor
def inject_skydns_counts():
    """Счётчики для боковой навигации — считаются, только если нужны."""
    if not current_user.is_authenticated:
        return {"skydns_counts": LazyCounts(dict, SKYDNS_COUNTS_EMPTY)}
    return {"skydns_counts": LazyCounts(_skydns_counts, SKYDNS_COUNTS_EMPTY)}


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

    # Категории угроз с счётчиками последней выгрузки — та же картина, что в
    # личном кабинете SkyDNS, но со ссылкой на разбор.
    danger_cats = (
        SkydnsCategory.query
        .filter(SkydnsCategory.is_dangerous.is_(True))
        .order_by(SkydnsCategory.requests.desc())
        .all()
    )
    danger_total = sum(c.requests for c in danger_cats) or 0

    return render_template(
        "skydns/dashboard.html",
        stats=stats,
        danger_cats=danger_cats,
        danger_total=danger_total,
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
        # В category лежит идентификатор основной категории, но домен может
        # относиться сразу к нескольким — ищем и по полному списку.
        query = query.filter(db.or_(
            ThreatDomain.category == category,
            ThreatDomain.cat_ids == category,
            ThreatDomain.cat_ids.like(f"{category},%"),
            ThreatDomain.cat_ids.like(f"%,{category},%"),
            ThreatDomain.cat_ids.like(f"%,{category}"),
        ))
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
    # Для фильтра нужны названия: в базе у домена лежит идентификатор.
    used = {row[0] for row in
            db.session.query(ThreatDomain.category)
            .filter(ThreatDomain.category != "").distinct().all()}
    catalogue = _catalogue()
    categories = sorted(
        (
            (code, (catalogue[int(code)].title
                    if code.isdigit() and int(code) in catalogue
                    else skydns_client.DANGEROUS_CATEGORY_IDS.get(
                        int(code), code) if code.isdigit() else code))
            for code in used
        ),
        key=lambda pair: pair[1],
    )
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
                source=HOST_SOURCE_SIEM,
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


def _lookup_worker(threat_ids: list[int], user_id: int):
    """Собрать исполнителя фонового поиска по списку доменов.

    Возвращает функцию для :mod:`app.services.jobs`: она получает ручку
    задания и отчитывается о ходе работы после каждого домена. Внутри — та
    же логика, что раньше выполнялась в обработчике запроса, но результат
    коммитится по одному домену: оператор видит найденные хосты сразу,
    не дожидаясь конца всей пачки.
    """

    def work(handle) -> str:
        config = load_siem_config()
        filter_template = get_siem_filter_template()
        group_field = get_siem_group_field()
        time_from, time_to = _window()

        done = failed = found = 0
        truncated_for: list[str] = []
        first_error = ""

        client = SiemClient(config)
        try:
            client.login()
        except SiemError as exc:
            for threat_id in threat_ids:
                threat = db.session.get(ThreatDomain, threat_id)
                db.session.add(SiemQueryLog(
                    threat_id=threat_id,
                    domain=threat.domain if threat else "",
                    status=JOB_FAILED, finished_at=datetime.utcnow(),
                    message=str(exc), period_from=time_from,
                    period_to=time_to, user_id=user_id,
                ))
            db.session.commit()
            client.close()
            raise JobError(str(exc)) from exc

        try:
            for index, threat_id in enumerate(threat_ids, start=1):
                threat = db.session.get(ThreatDomain, threat_id)
                if threat is None:
                    continue
                handle.progress(processed=index - 1,
                                detail=f"Ищу {threat.domain}")

                log = SiemQueryLog(
                    threat_id=threat.id, domain=threat.domain,
                    period_from=time_from, period_to=time_to, user_id=user_id,
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
                    first_error = first_error or f"{threat.domain}: {exc}"
                    db.session.commit()
                    handle.progress(processed=index, failed=failed, found=found)
                    continue

                db.session.flush()  # закрепить журнал до вставки хостов
                total_hosts = _apply_hits(threat, result.hosts)
                threat.siem_checked_at = datetime.utcnow()
                threat.siem_hosts_count = total_hosts
                found += len(result.hosts)

                log.status = JOB_SUCCESS
                log.finished_at = datetime.utcnow()
                log.hosts_found = len(result.hosts)
                log.events_total = result.total_count
                log.query_filter = result.query_filter
                log.message = (
                    f"Найдено хостов: {len(result.hosts)}; событий прочитано: "
                    f"{result.events_read} из {result.total_count}."
                )
                if result.truncated:
                    # Постранично ответ не дочитывается, поэтому молчать об
                    # этом нельзя: часть хостов могла не попасть в выборку.
                    log.message += (
                        f" Дочитано не всё: предел {config.limit} событий "
                        "на домен. Часть хостов могла не войти — сузьте окно "
                        "поиска или поднимите предел в настройках."
                    )
                    truncated_for.append(threat.domain)
                done += 1
                db.session.commit()
                handle.progress(processed=index, failed=failed, found=found)
        finally:
            client.close()
            db.session.commit()

        summary = f"Проверено доменов: {done}. Найдено хостов: {found}."
        if failed:
            summary += f" Не удалось проверить: {failed}. {first_error}"
        if truncated_for:
            summary += (
                f" Ответ SIEM усечён по пределу {config.limit} событий "
                f"для доменов: {', '.join(truncated_for[:5])}."
            )
        if not found and not failed:
            # Ноль хостов — это не обязательно «никто не ходил»: чаще всего
            # не совпало поле группировки. Подсказываем, куда смотреть.
            summary += (
                " Хостов не найдено. Если они точно должны быть, откройте "
                "«Настройки → Диагностика запроса в SIEM» — там видно, что "
                "SIEM ответил на самом деле."
            )
        return summary

    return work


def _start_lookup(threats: list[ThreatDomain], back_url: str):
    """Запустить фоновый поиск и вернуть оператора на страницу."""
    running = active_job(JOB_KIND_SIEM)
    if running is not None:
        flash(
            f"Поиск в SIEM уже идёт ({running.processed} из {running.total}). "
            "Дождитесь его окончания — второй запрос только замедлит SIEM.",
            "warning",
        )
        return redirect(back_url)

    ids = [t.id for t in threats]
    domains = ", ".join(t.domain for t in threats[:3])
    if len(threats) > 3:
        domains += f" и ещё {len(threats) - 3}"

    start_job(
        current_app._get_current_object(),
        kind=JOB_KIND_SIEM,
        service_id="skydns",
        title=f"Поиск конечных хостов в SIEM: {domains}",
        total=len(ids),
        user_id=current_user.id,
        target_url=url_for("skydns.hosts"),
        worker=_lookup_worker(ids, current_user.id),
    )
    flash(
        f"Поиск в SIEM запущен в фоне ({len(ids)} дом.). "
        "Можно продолжать работу — о результате портал сообщит сам.",
        "info",
    )
    return redirect(back_url)


@skydns_bp.route("/domains/<int:threat_id>/lookup", methods=["POST"])
@operator_required
def threat_lookup(threat_id: int):
    threat = db.get_or_404(ThreatDomain, threat_id)
    return _start_lookup(
        [threat], url_for("skydns.threat_view", threat_id=threat.id)
    )


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

    return _start_lookup(threats, _back_url())


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

def _catalogue() -> dict:
    """Справочник категорий SkyDNS из базы."""
    return {cat.id: cat for cat in SkydnsCategory.query.all()}


def _tracked_ids() -> list:
    """ID категорий, попадающих в разбор.

    Основной источник — флаг ``is_dangerous`` из ответа SkyDNS; ручное
    переопределение в справочнике важнее его.
    """
    rows = SkydnsCategory.query.all()
    if not rows:
        # Справочник ещё не загружен — берём перечень из инструкции.
        return sorted(skydns_client.DANGEROUS_CATEGORY_IDS)
    return sorted(cat.id for cat in rows if cat.is_tracked)


def _sync_categories(client, start: date, end: date) -> int:
    """Обновить справочник категорий. Возвращает число опасных категорий."""
    categories = client.categories(start, end)
    known = _catalogue()
    for item in categories:
        row = known.get(item.id)
        if row is None:
            row = SkydnsCategory(id=item.id)
            db.session.add(row)
        row.title = item.title or row.title or ""
        row.is_dangerous = item.is_dangerous
        row.requests = item.requests
        row.blocks = item.blocks
    db.session.commit()
    return sum(1 for c in categories if c.is_dangerous)


def _recount_categories() -> None:
    """Пересчитать, сколько доменов набралось в каждой категории."""
    counts: dict = {}
    for threat in ThreatDomain.query.all():
        for raw in (threat.cat_ids or "").split(","):
            raw = raw.strip()
            if raw.isdigit():
                counts[int(raw)] = counts.get(int(raw), 0) + 1
    for row in SkydnsCategory.query.all():
        row.domains_count = counts.get(row.id, 0)
    db.session.commit()


def _upsert_stats(stats, source: str, tracked: set | None = None,
                  user_id: int | None = None) -> tuple:
    """Сохранить статистику по доменам.

    ``tracked`` — множество ID отслеживаемых категорий. Если оно задано,
    домен без пересечения с ним пропускается (API уже фильтрует по ``cats``,
    но отчёт может содержать и смежные категории домена).

    Возвращает ``(сохранено, новых, отсеяно правилами)``.
    """
    catalogue = _catalogue()
    matcher = Matcher()
    now = datetime.utcnow()
    if user_id is None:
        # В фоновом задании контекста запроса нет — автора передают явно.
        user_id = current_user.id if current_user.is_authenticated else None
    total = new = skipped = 0

    for stat in stats:
        cat_ids = [int(c) for c in (stat.cat_ids or [])]
        if tracked is not None and cat_ids and not (set(cat_ids) & tracked):
            continue
        if matcher.excluded(stat.domain):
            skipped += 1
            continue

        primary, titles = skydns_client.describe_categories(cat_ids, catalogue)
        total += 1
        threat = ThreatDomain.query.filter_by(domain=stat.domain).first()
        if threat is None:
            threat = ThreatDomain(
                domain=stat.domain,
                root_domain=dm.registrable(stat.domain),
                first_seen=now,
                source=source,
                added_by=user_id,
                # Значения по умолчанию проставляются только при вставке,
                # а счётчики нужны прямо сейчас — ниже идёт сравнение.
                requests_count=0,
                blocks_count=0,
            )
            db.session.add(threat)
            new += 1
        threat.last_seen = now
        if not threat.root_domain:
            threat.root_domain = dm.registrable(threat.domain)
        # Счётчики приходят за период выборки — берём максимум, а не затираем.
        threat.requests_count = max(threat.requests_count or 0, stat.requests)
        threat.blocks_count = max(threat.blocks_count or 0, stat.blocks)
        if cat_ids:
            threat.cat_ids = _merge_cat_ids(threat.cat_ids, cat_ids)
        # Категория из CSV/ручного ввода приходит строкой, из API — списком id.
        threat.category = primary or stat.category or threat.category
        threat.category_title = titles or stat.category_title or threat.category_title

    matcher.save_hits()
    db.session.commit()
    return total, new, skipped


def _merge_cat_ids(stored: str, incoming: list) -> str:
    """Объединить категории домена, а не заменять их.

    При сборе по срезам один и тот же домен приезжает из нескольких запросов
    (по одному на категорию), и каждый ответ знает только про свою. Затирая
    список, мы бы оставили домену последнюю увиденную категорию.
    """
    known = {int(part) for part in (stored or "").split(",")
             if part.strip().lstrip("-").isdigit()}
    known.update(int(c) for c in incoming)
    return ",".join(str(c) for c in sorted(known))


def _apply_devices(threat: ThreatDomain, devices) -> tuple:
    """Сохранить устройства SkyDNS как конечные хосты.

    Записи с ``token == 0`` — трафик через шлюз: конечный хост по ним
    неизвестен, их считаем отдельно и показываем как повод идти в SIEM.
    """
    existing = {host.address: host for host in threat.hosts}
    now = datetime.utcnow()
    added = gateway = 0

    for device in devices:
        if device.is_gateway:
            gateway += 1
            continue
        for address in device.addresses:
            host = existing.get(address)
            if host is None:
                host = ThreatHost(
                    threat_id=threat.id,
                    address=address,
                    source=HOST_SOURCE_SKYDNS,
                    events_count=0,
                    first_seen=now,
                )
                db.session.add(host)
                existing[address] = host
                added += 1
            host.events_count = max(host.events_count or 0, device.requests)
            host.device_token = str(device.token)
            host.last_seen = now
            host.found_at = now
    return added, gateway


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
        categories=SkydnsCategory.query.order_by(
            SkydnsCategory.is_dangerous.desc(), SkydnsCategory.title
        ).all(),
        tracked_count=len(_tracked_ids()),
        skydns_configured=load_skydns_config().is_configured,
        recent=SkydnsSyncLog.query.order_by(
            SkydnsSyncLog.started_at.desc()
        ).limit(10).all(),
    )


def _do_api_sync(form):
    """Запустить выгрузку из SkyDNS фоновым заданием."""
    start = form.start.data or date.today() - timedelta(days=DEFAULT_SYNC_DAYS)
    end = form.end.data or date.today()
    if start > end:
        flash("Начало периода позже его конца.", "danger")
        return redirect(url_for("skydns.sync"))

    running = active_job(JOB_KIND_SKYDNS)
    if running is not None:
        flash("Выгрузка из SkyDNS уже идёт — дождитесь её окончания.", "warning")
        return redirect(url_for("skydns.sync"))

    deep = bool(request.form.get("deep"))
    days = (end - start).days + 1
    tracked = _tracked_ids()
    # Полный сбор идёт срезами «категория × день»: столько отчётов и будет.
    steps = (len(tracked) * days) if deep else 1

    start_job(
        current_app._get_current_object(),
        kind=JOB_KIND_SKYDNS,
        service_id="skydns",
        title=("Полная выгрузка из SkyDNS" if deep else "Выгрузка из SkyDNS")
              + f": {start:%d.%m} — {end:%d.%m}",
        total=steps + 2,          # +справочник категорий, +устройства
        user_id=current_user.id,
        target_url=url_for("skydns.domains"),
        worker=_sync_worker(start, end, current_user.id, deep=deep),
    )
    flash(
        "Выгрузка запущена в фоне. Можно продолжать работу — о результате "
        "портал сообщит сам.",
        "info",
    )
    return redirect(url_for("skydns.sync"))


def _day_range(start: date, end: date):
    day = start
    while day <= end:
        yield day
        day += timedelta(days=1)


def _sync_worker(start: date, end: date, user_id: int, deep: bool):
    """Исполнитель выгрузки из SkyDNS.

    Обычный режим — один отчёт по всем отслеживаемым категориям за период:
    быстро, но API отдаёт только вершину списка, и всё, что не поместилось
    в лимит, теряется молча.

    Полный сбор режет запрос на срезы «одна категория × одни сутки». Лимит
    применяется к каждому срезу отдельно, поэтому за один прогон забирается
    в десятки раз больше имён: девять категорий за неделю — это 63 отчёта
    по столько-то доменов вместо одного общего. Срез, который всё-таки упёрся
    в лимит, попадает в итог поимённо — значит, там ещё есть что забрать.
    """

    def work(handle):
        client = SkydnsClient(load_skydns_config())
        log = SkydnsSyncLog(
            source=THREAT_SOURCE_API, period_from=start, period_to=end,
            user_id=user_id,
        )
        db.session.add(log)
        db.session.commit()

        limit = get_int(KEY_SKYDNS_LIMIT, DEFAULT_SKYDNS_LIMIT)
        done = 0

        try:
            handle.progress(processed=0, detail="Справочник категорий")
            dangerous = _sync_categories(client, start, end)
            tracked = _tracked_ids()
            if not tracked:
                raise SkydnsError(
                    "Ни одна категория не отмечена как отслеживаемая — "
                    "проверьте справочник категорий."
                )
            done = 1
            handle.progress(processed=done)

            merged: dict = {}
            full_slices: list[str] = []
            titles = {c.id: c.title for c in SkydnsCategory.query.all()}

            for cats, day_from, day_to, label in _slices(tracked, start, end,
                                                         deep, titles):
                handle.progress(processed=done, detail=f"Домены: {label}")
                chunk = client.domains(day_from, day_to, cats=cats, limit=limit)
                for stat in chunk:
                    _merge_stat(merged, stat)
                if len(chunk) >= limit:
                    full_slices.append(label)
                done += 1
                handle.progress(processed=done, found=len(merged))
        finally:
            db.session.commit()

        stats = list(merged.values())
        total, new, skipped = _upsert_stats(
            stats, THREAT_SOURCE_API, tracked=set(tracked), user_id=user_id,
        )
        _recount_categories()

        handle.progress(processed=done + 1, detail="Устройства SkyDNS",
                        found=total)
        devices_found = 0
        if get_bool(KEY_SKYDNS_AUTO_DEVICES, True) and total:
            devices_found = _collect_devices(client, start, end, tracked)

        summary = (
            f"Отслеживаемых категорий: {len(tracked)} (опасных в справочнике: "
            f"{dangerous}). Уникальных доменов в ответах: {len(stats)}; "
            f"сохранено: {total}; новых: {new}; "
            f"хостов от SkyDNS: {devices_found}."
        )
        if skipped:
            summary += f" Отсеяно правилами исключений: {skipped}."
        if full_slices:
            # Срез, упёршийся в лимит, — единственный признак того, что за
            # период осталось что-то незабранное. Молчать о нём нельзя.
            summary += (
                f" Упёрлись в лимит {limit} срезов: {len(full_slices)} "
                f"({', '.join(full_slices[:4])}) — поднимите лимит доменов "
                "в настройках или сузьте период."
            )
        elif not deep:
            summary += (" Это быстрая выгрузка: забрана вершина списка. "
                        "Полный сбор — кнопка «Собрать всё».")

        log.status = JOB_SUCCESS
        log.finished_at = datetime.utcnow()
        log.domains_total = total
        log.domains_new = new
        log.message = summary
        db.session.commit()
        return summary

    return work


def _slices(tracked: list, start: date, end: date, deep: bool, titles: dict):
    """Из чего складывается выгрузка: список запросов к API.

    Отдаёт кортежи ``(категории, начало, конец, подпись)``.
    """
    if not deep:
        yield list(tracked), start, end, "все категории за период"
        return
    for cat in tracked:
        name = titles.get(cat) or f"категория {cat}"
        for day in _day_range(start, end):
            yield [cat], day, day, f"{name} · {day:%d.%m}"


def _merge_stat(merged: dict, stat) -> None:
    """Свести одинаковые домены из разных срезов в одну запись.

    Счётчики складываются (срезы не пересекаются по дням), категории
    объединяются: каждый срез знает только про свою.
    """
    known = merged.get(stat.domain)
    if known is None:
        merged[stat.domain] = stat
        return
    known.requests += stat.requests
    known.blocks += stat.blocks
    for cat in stat.cat_ids:
        if cat not in known.cat_ids:
            known.cat_ids.append(cat)


def _collect_devices(client, start: date, end: date, tracked: list) -> int:
    """Найти устройства по всем доменам разом.

    Раньше устройства запрашивались по одному домену за раз — это отдельный
    отчёт SkyDNS на каждый домен, и выгрузка растягивалась на минуты. Теперь
    берётся одна детализация, в которой уже есть и домен, и адрес устройства.
    """
    try:
        mapping = client.hosts_by_domain(
            start, end, cats=tracked,
            limit=get_int(KEY_SKYDNS_DETAIL_LIMIT, DEFAULT_DETAIL_LIMIT),
        )
    except SkydnsError:
        current_app.logger.exception("Не удалось получить детализацию SkyDNS")
        return 0

    if not mapping:
        return 0

    threats = (
        ThreatDomain.query
        .filter(ThreatDomain.domain.in_(list(mapping)))
        .all()
    )
    found = 0
    for threat in threats:
        added, _gateway = _apply_devices(threat, mapping.get(threat.domain, []))
        if added:
            db.session.flush()
            threat.siem_hosts_count = threat.hosts.count()
            found += added
    db.session.commit()
    return found


def _do_csv_import(form):
    log = SkydnsSyncLog(source=THREAT_SOURCE_CSV, user_id=current_user.id)
    db.session.add(log)

    data = form.report.data.read()
    try:
        stats = skydns_client.parse_csv(data)
    except SkydnsError as exc:
        log.status = JOB_FAILED
        log.finished_at = datetime.utcnow()
        log.message = str(exc)
        db.session.commit()
        flash(str(exc), "danger")
        return redirect(url_for("skydns.sync"))

    total, new, skipped = _upsert_stats(stats, THREAT_SOURCE_CSV)
    log.status = JOB_SUCCESS
    log.finished_at = datetime.utcnow()
    log.domains_total = total
    log.domains_new = new
    log.message = (
        f"Строк в файле: {len(stats)}; сохранено: {total}; новых: {new}."
        + (f" Отсеяно правилами: {skipped}." if skipped else "")
    )
    db.session.commit()
    flash(
        f"Из файла разобрано строк: {len(stats)}. "
        f"Сохранено доменов: {total}, из них новых: {new}."
        + (f" Отсеяно правилами исключений: {skipped}." if skipped else ""),
        "success",
    )
    return redirect(url_for("skydns.domains"))


def _do_manual_add(form):
    raw = [line.strip().lower() for line in (form.values.data or "").splitlines()]
    category = (form.category.data or "добавлен вручную").strip()
    stats = [
        skydns_client.DomainStat(
            domain=line.strip(".").lstrip("*."),
            category=category,
            category_title=category,
        )
        for line in raw
        if line and "." in line and not line.startswith("#")
    ]
    if not stats:
        flash("Не найдено ни одного корректного домена.", "danger")
        return redirect(url_for("skydns.sync"))

    total, new, skipped = _upsert_stats(stats, THREAT_SOURCE_MANUAL)
    if skipped:
        # Молча не добавить домен, который оператор ввёл руками, — худшее,
        # что можно сделать: он решит, что портал сломан.
        flash(
            f"Не добавлено из-за правил исключений: {skipped}. "
            "Правила — в разделе «Исключения».",
            "warning",
        )
    flash(f"Добавлено доменов: {total}, из них новых: {new}.", "success")
    return redirect(url_for("skydns.domains"))


# --- Справочник категорий -------------------------------------------------

@skydns_bp.route("/categories", methods=["GET", "POST"])
@login_required
def categories():
    """Справочник категорий SkyDNS и выбор отслеживаемых."""
    if request.method == "POST":
        if not current_user.is_operator:
            flash("Изменение доступно только операторам.", "danger")
            return redirect(url_for("skydns.categories"))
        tracked = {int(v) for v in request.form.getlist("tracked", type=int)}
        for cat in SkydnsCategory.query.all():
            wanted = cat.id in tracked
            # Храним только осознанное отличие от флага SkyDNS.
            cat.track_override = None if wanted == cat.is_dangerous else wanted
        db.session.commit()
        flash("Список отслеживаемых категорий сохранён.", "success")
        return redirect(url_for("skydns.categories"))

    return render_template(
        "skydns/categories.html",
        items=SkydnsCategory.query.order_by(
            SkydnsCategory.is_dangerous.desc(), SkydnsCategory.title
        ).all(),
        fallback=skydns_client.DANGEROUS_CATEGORY_IDS,
    )


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


# --- Настройки сервиса ----------------------------------------------------

def _siem_form() -> SiemSettingsForm:
    return SiemSettingsForm(
        base_url=get_setting(KEY_SIEM_URL),
        auth_mode=get_setting(KEY_SIEM_AUTH_MODE, "session"),
        auth_type=get_setting(KEY_SIEM_AUTH_TYPE, "local"),
        username=get_setting(KEY_SIEM_USERNAME),
        client_id=get_setting(KEY_SIEM_CLIENT_ID, "mpx"),
        verify_ssl=get_bool(KEY_SIEM_VERIFY, False),
        filter_template=get_setting(KEY_SIEM_FILTER, DEFAULT_SIEM_FILTER),
        group_field=get_setting(KEY_SIEM_GROUP_FIELD, DEFAULT_SIEM_GROUP_FIELD),
        window_hours=get_int(KEY_SIEM_WINDOW, DEFAULT_WINDOW_HOURS),
        max_events=get_int(KEY_SIEM_MAX_EVENTS, DEFAULT_SIEM_MAX_EVENTS),
        timeout=get_int(KEY_SIEM_TIMEOUT, DEFAULT_SIEM_TIMEOUT),
    )


def _skydns_form() -> SkydnsSettingsForm:
    from ..services.skydns_client import DEFAULT_BASE_URL

    return SkydnsSettingsForm(
        base_url=get_setting(KEY_SKYDNS_URL, DEFAULT_BASE_URL),
        user_id=get_setting(KEY_SKYDNS_USER_ID),
        profile_ids=get_setting(KEY_SKYDNS_PROFILE),
        timezone=get_setting(KEY_SKYDNS_TZ, DEFAULT_SKYDNS_TZ),
        days=get_int(KEY_SKYDNS_DAYS, DEFAULT_SYNC_DAYS),
        limit=get_int(KEY_SKYDNS_LIMIT, DEFAULT_SKYDNS_LIMIT),
        detail_limit=get_int(KEY_SKYDNS_DETAIL_LIMIT, DEFAULT_DETAIL_LIMIT),
        report_timeout=get_int(KEY_SKYDNS_TIMEOUT, 300),
        auto_devices=get_bool(KEY_SKYDNS_AUTO_DEVICES, True),
        verify_ssl=get_bool(KEY_SKYDNS_VERIFY, True),
    )


@skydns_bp.route("/settings", methods=["GET", "POST"])
@operator_required
def settings():
    """Настройки сервиса: подключения к SkyDNS и MaxPatrol SIEM."""
    siem_form = _siem_form()
    skydns_form = _skydns_form()

    def _render():
        return render_template(
            "skydns/settings.html",
            siem_form=siem_form,
            skydns_form=skydns_form,
            siem_password_set=bool(get_setting(KEY_SIEM_PASSWORD)),
            skydns_token_set=bool(get_setting(KEY_SKYDNS_TOKEN)),
            siem_filter_default=DEFAULT_SIEM_FILTER,
            probe_methods=PROBE_METHODS,
            siem_probe_form=SiemProbeForm(),
        )

    if (siem_form.submit_siem.data or siem_form.test_siem.data) \
            and siem_form.validate_on_submit():
        _save_siem(siem_form)
        db.session.commit()
        if siem_form.test_siem.data:
            _test_siem()
            return _render()
        flash("Настройки MaxPatrol SIEM сохранены.", "success")
        return redirect(url_for("skydns.settings"))

    if (skydns_form.submit_skydns.data or skydns_form.test_skydns.data) \
            and skydns_form.validate_on_submit():
        _save_skydns(skydns_form)
        db.session.commit()
        if skydns_form.test_skydns.data:
            _test_skydns()
            return _render()
        flash("Настройки SkyDNS сохранены.", "success")
        return redirect(url_for("skydns.settings"))

    return _render()


def _save_siem(form) -> None:
    set_setting(KEY_SIEM_URL, (form.base_url.data or "").strip())
    set_setting(KEY_SIEM_AUTH_MODE, form.auth_mode.data or "session")
    set_setting(KEY_SIEM_AUTH_TYPE, form.auth_type.data or "local")
    set_setting(KEY_SIEM_USERNAME, (form.username.data or "").strip())
    set_setting(KEY_SIEM_CLIENT_ID, (form.client_id.data or "").strip())
    set_setting(KEY_SIEM_VERIFY, "1" if form.verify_ssl.data else "0")
    set_setting(KEY_SIEM_FILTER,
                (form.filter_template.data or DEFAULT_SIEM_FILTER).strip())
    set_setting(KEY_SIEM_GROUP_FIELD,
                (form.group_field.data or DEFAULT_SIEM_GROUP_FIELD).strip())
    if form.window_hours.data:
        set_setting(KEY_SIEM_WINDOW, str(form.window_hours.data))
    if form.max_events.data:
        set_setting(KEY_SIEM_MAX_EVENTS, str(form.max_events.data))
    if form.timeout.data:
        set_setting(KEY_SIEM_TIMEOUT, str(form.timeout.data))
    # Секреты перезаписываются, только если их ввели заново.
    if form.password.data:
        set_setting(KEY_SIEM_PASSWORD, form.password.data, is_secret=True)
    if form.client_secret.data:
        set_setting(KEY_SIEM_CLIENT_SECRET, form.client_secret.data, is_secret=True)


def _save_skydns(form) -> None:
    set_setting(KEY_SKYDNS_URL, (form.base_url.data or "").strip())
    set_setting(KEY_SKYDNS_USER_ID, (form.user_id.data or "").strip())
    set_setting(KEY_SKYDNS_PROFILE, (form.profile_ids.data or "").strip())
    set_setting(KEY_SKYDNS_TZ, (form.timezone.data or DEFAULT_SKYDNS_TZ).strip())
    set_setting(KEY_SKYDNS_VERIFY, "1" if form.verify_ssl.data else "0")
    set_setting(KEY_SKYDNS_AUTO_DEVICES, "1" if form.auto_devices.data else "0")
    if form.days.data:
        set_setting(KEY_SKYDNS_DAYS, str(form.days.data))
    if form.limit.data:
        set_setting(KEY_SKYDNS_LIMIT, str(form.limit.data))
    if form.detail_limit.data:
        set_setting(KEY_SKYDNS_DETAIL_LIMIT, str(form.detail_limit.data))
    if form.report_timeout.data:
        set_setting(KEY_SKYDNS_TIMEOUT, str(form.report_timeout.data))
    if form.token.data:
        set_setting(KEY_SKYDNS_TOKEN, form.token.data.strip(), is_secret=True)


@skydns_bp.route("/settings/siem-probe", methods=["POST"])
@operator_required
def siem_probe():
    """Показать сырой запрос и ответ SIEM по одному домену.

    Отдельная страница, а не всплывающее сообщение: ответ бывает длинным,
    и разбирать его удобнее целиком.
    """
    form = SiemProbeForm()
    if not form.validate_on_submit():
        flash("Укажите домен для диагностики.", "danger")
        return redirect(url_for("skydns.settings"))

    time_from, time_to = _window()
    client = SiemClient(load_siem_config())
    try:
        client.login()
        report = client.probe(
            form.domain.data, time_from, time_to,
            get_siem_filter_template(), get_siem_group_field(),
        )
    except SiemError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("skydns.settings"))
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Ошибка диагностики SIEM")
        flash(f"Непредвиденная ошибка диагностики: {exc}", "danger")
        return redirect(url_for("skydns.settings"))
    finally:
        client.close()

    return render_template(
        "skydns/siem_probe.html",
        domain=form.domain.data,
        report=report,
        raw=json.dumps(report, ensure_ascii=False, indent=2, default=str),
        period_from=time_from,
        period_to=time_to,
    )


def _test_siem() -> None:
    """Проверить вход в SIEM без выполнения поискового запроса."""
    try:
        client = SiemClient(load_siem_config())
        client.login()
        client.close()
    except SiemError as exc:
        flash(str(exc), "danger")
        return
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Ошибка проверки подключения к SIEM")
        flash(f"Непредвиденная ошибка проверки SIEM: {exc}", "danger")
        return
    flash("Подключение к MaxPatrol SIEM успешно: вход выполнен.", "success")


@skydns_bp.route("/settings/probe", methods=["POST"])
@operator_required
def settings_probe():
    """Показать сырой ответ метода SkyDNS — для разбора формата."""
    method = (request.form.get("method") or "").strip()
    if method not in PROBE_METHODS:
        flash("Неизвестный метод диагностики.", "danger")
        return redirect(url_for("skydns.settings"))

    days = get_int(KEY_SKYDNS_DAYS, DEFAULT_SYNC_DAYS)
    end = date.today()
    start = end - timedelta(days=days)
    try:
        result = SkydnsClient(load_skydns_config()).probe(method, start, end)
    except SkydnsError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("skydns.settings"))
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Ошибка диагностики SkyDNS")
        flash(f"Непредвиденная ошибка диагностики: {exc}", "danger")
        return redirect(url_for("skydns.settings"))

    return render_template(
        "skydns/probe.html",
        method=method,
        methods=PROBE_METHODS,
        period=(start, end),
        result=result,
        pretty=json.dumps(result.get("response"), ensure_ascii=False, indent=2),
        request_pretty=json.dumps(result.get("request"), ensure_ascii=False,
                                  indent=2),
    )


def _test_skydns() -> None:
    """Проверить токен SkyDNS лёгким методом get_total_activity."""
    today = date.today()
    try:
        totals = SkydnsClient(load_skydns_config()).total_activity(today, today)
    except SkydnsError as exc:
        flash(str(exc), "danger")
        return
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Ошибка проверки подключения к SkyDNS")
        flash(f"Непредвиденная ошибка проверки SkyDNS: {exc}", "danger")
        return
    flash(
        "Подключение к SkyDNS успешно. За сегодня запросов: "
        f"{totals.get('requests', 0)}, блокировок: {totals.get('blocks', 0)}, "
        f"опасных запросов: {totals.get('dangerous_requests', 0)}.",
        "success",
    )
