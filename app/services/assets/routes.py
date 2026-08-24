"""Сервис «Узлы сети» — что за узел стоит за адресом.

Задача, которую он решает. В работе постоянно всплывает голый IP: пришёл из
статистики SkyDNS, из события SIEM, из чужого письма. Дальше нужно понять, что
это за машина, где она стоит и чья она. Раньше это делалось руками через чужие
консоли; здесь это один запрос к собственной базе.

Откуда берутся данные:

  * **аренды DHCP** — единственный источник связки «адрес → имя → MAC».
    Обратных записей DNS для рабочих станций в домене нет (проверено на живых
    адресах), так что заменить их нечем;
  * **Active Directory** — что за машина носит это имя: подразделение,
    описание, операционная система, дата последнего входа.

База наполняется выгрузкой по расписанию, а отдельной кнопкой любой адрес
можно проверить прямо сейчас — выгрузка могла устареть, аренда меняется.

Все обращения к внешним системам — только чтение.
"""
from __future__ import annotations

from datetime import datetime

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
from sqlalchemy import func, or_

from ...core.background import JobError, active_job
from ...core.background import start as start_job
from ...core.extensions import db
from ...core.models import JOB_KIND_ASSETS_AD, JOB_KIND_ASSETS_DHCP
from ...core.web_utils import (
    WRITE_BATCH,
    LazyCounts,
    csv_response,
    operator_required,
    service_guard,
)
from .forms import (
    AdSettingsForm,
    DhcpSettingsForm,
    HostNotesForm,
    ManualHostForm,
    SyncForm,
)
from .lib import classify, inventory
from .lib.dhcp_client import DhcpClient, DhcpError
from .lib.ipaddr import (
    is_hostname,
    looks_like_mac,
    normalize_mac,
    parse_ip,
    short_name,
)
from .lib.ldap_client import LdapClient, LdapError
from .models import (
    SOURCE_AD,
    SOURCE_DHCP,
    SOURCE_MANUAL,
    AdComputer,
    AssetLookup,
    AssetSyncLog,
    DhcpScope,
    HostObservation,
    NetworkHost,
)
from .settings import (
    DEFAULT_AD_PORT,
    DEFAULT_AD_TIMEOUT,
    DEFAULT_DHCP_PORT,
    DEFAULT_DHCP_TIMEOUT,
    KEY_AD_BASE_DN,
    KEY_AD_DOMAIN,
    KEY_AD_HOST,
    KEY_AD_PASSWORD,
    KEY_AD_PORT,
    KEY_AD_SSL,
    KEY_AD_TIMEOUT,
    KEY_AD_USER,
    KEY_DHCP_HOST,
    KEY_DHCP_PASSWORD,
    KEY_DHCP_PORT,
    KEY_DHCP_DISCOVER,
    KEY_DHCP_SERVERS,
    KEY_DHCP_SSL,
    KEY_DHCP_TIMEOUT,
    KEY_DHCP_USER,
    allowed_servers,
    discover_servers,
    get_setting,
    load_dhcp_config,
    load_ldap_config,
    set_setting,
    target_servers,
)

assets_bp = Blueprint("assets", __name__, url_prefix="/assets",
                      template_folder="templates")
assets_bp.before_request(service_guard("assets"))

PER_PAGE = 100

#: Сколько записей показываем в быстрых списках дашборда.
RECENT_LIMIT = 10


# --- счётчики для навигации ------------------------------------------------

ASSETS_COUNTS_EMPTY = {"hosts": 0, "computers": 0, "scopes": 0, "unlinked": 0}


def _assets_counts() -> dict:
    return {
        "hosts": NetworkHost.query.count(),
        "computers": AdComputer.query.count(),
        "scopes": DhcpScope.query.count(),
        "unlinked": NetworkHost.query.filter(
            NetworkHost.ad_computer_id.is_(None)
        ).count(),
    }


@assets_bp.app_context_processor
def inject_assets_counts():
    if not current_user.is_authenticated:
        return {"assets_counts": LazyCounts(dict, ASSETS_COUNTS_EMPTY)}
    return {"assets_counts": LazyCounts(_assets_counts, ASSETS_COUNTS_EMPTY)}


# --- дашборд ---------------------------------------------------------------

@assets_bp.route("/")
@login_required
def dashboard():
    last_dhcp = (AssetSyncLog.query.filter_by(source="dhcp")
                 .order_by(AssetSyncLog.started_at.desc()).first())
    last_ad = (AssetSyncLog.query.filter_by(source="ad")
               .order_by(AssetSyncLog.started_at.desc()).first())

    by_kind = dict(
        db.session.query(NetworkHost.kind, func.count(NetworkHost.id))
        .group_by(NetworkHost.kind).all()
    )
    kinds = [
        {"kind": kind, "title": classify.title(kind),
         "badge": classify.badge(kind), "count": by_kind.get(kind, 0)}
        for kind in (classify.KIND_WORKSTATION, classify.KIND_SERVER,
                     classify.KIND_DC, classify.KIND_NETWORK,
                     classify.KIND_PRINTER, classify.KIND_UNKNOWN)
        if by_kind.get(kind, 0)
    ]

    return render_template(
        "assets/dashboard.html",
        counts=_assets_counts(),
        kinds=kinds,
        last_dhcp=last_dhcp,
        last_ad=last_ad,
        ad_configured=load_ldap_config().is_configured,
        dhcp_configured=load_dhcp_config().is_configured,
        recent_lookups=(AssetLookup.query
                        .order_by(AssetLookup.created_at.desc())
                        .limit(RECENT_LIMIT).all()),
        recent_changes=(HostObservation.query
                        .order_by(HostObservation.seen_at.desc())
                        .limit(RECENT_LIMIT).all()),
    )


# --- поиск -----------------------------------------------------------------

def _query_kind(text: str) -> str:
    if parse_ip(text):
        return "ip"
    if looks_like_mac(text):
        return "mac"
    if is_hostname(text):
        return "hostname"
    return "text"


def _log_lookup(query: str, kind: str, *, found: bool, result: str = "",
                host: NetworkHost | None = None, is_live: bool = False,
                error: str = "") -> None:
    """Записать обращение в журнал.

    Журнал ведётся ради работы, а не контроля: при разборе инцидента полезно
    видеть, что этот адрес уже смотрели и что тогда нашли.
    """
    db.session.add(AssetLookup(
        term=(query or "")[:255],
        query_kind=kind,
        is_live=is_live,
        found=found,
        result=(result or "")[:500],
        error=(error or "")[:1000],
        host=host,
        user_id=current_user.id if current_user.is_authenticated else None,
    ))


@assets_bp.route("/search")
@login_required
def search():
    """Единая строка поиска: адрес, имя, MAC или кусок описания."""
    text = (request.args.get("q") or "").strip()
    if not text:
        return render_template("assets/search.html", q="", hosts=[],
                               computers=[], kind="", searched=False)

    kind = _query_kind(text)
    hosts, computers = _find(text, kind)

    # Обращение записываем один раз на поиск, а не на каждую перерисовку
    # страницы: браузер возвращается сюда кнопкой «назад», и журнал распух бы.
    if not request.args.get("page"):
        summary = ""
        if hosts:
            summary = "%s → %s" % (hosts[0].ip, hosts[0].display_name or "имя неизвестно")
        elif computers:
            summary = computers[0].name
        _log_lookup(text, kind, found=bool(hosts or computers), result=summary,
                    host=hosts[0] if hosts else None)
        db.session.commit()

    return render_template(
        "assets/search.html",
        q=text,
        kind=kind,
        hosts=hosts,
        computers=computers,
        searched=True,
        exact_ip=parse_ip(text),
    )


def _find(text: str, kind: str) -> tuple[list, list]:
    """Поиск по собственной базе. Внешние системы здесь не трогаем."""
    hosts_query = NetworkHost.query
    computers: list = []

    if kind == "ip":
        hosts_query = hosts_query.filter(NetworkHost.ip == parse_ip(text))
    elif kind == "mac":
        hosts_query = hosts_query.filter(NetworkHost.mac == normalize_mac(text))
    else:
        pattern = "%%%s%%" % text.lower()
        hosts_query = hosts_query.filter(or_(
            NetworkHost.hostname.ilike(pattern),
            NetworkHost.ip.ilike(pattern),
            NetworkHost.notes.ilike(pattern),
        ))
        computers = (
            AdComputer.query
            .filter(or_(AdComputer.name.ilike(pattern),
                        AdComputer.description.ilike(pattern),
                        AdComputer.ou_path.ilike(pattern)))
            .order_by(AdComputer.name).limit(PER_PAGE).all()
        )

    hosts = hosts_query.order_by(NetworkHost.ip_int).limit(PER_PAGE).all()

    # Машины, найденные по адресу или MAC, тоже показываем карточкой AD.
    if kind in ("ip", "mac") and hosts and not computers:
        computers = [h.ad_computer for h in hosts if h.ad_computer is not None]
    return hosts, computers


# --- список адресов --------------------------------------------------------

@assets_bp.route("/hosts")
@login_required
def hosts():
    query = _hosts_query()
    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(NetworkHost.ip_int).paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )
    return render_template(
        "assets/hosts.html",
        items=pagination.items,
        pagination=pagination,
        q=(request.args.get("q") or "").strip(),
        kind=request.args.get("kind", ""),
        scope=request.args.get("scope", ""),
        kinds=classify.KIND_TITLES,
        scopes=DhcpScope.query.order_by(DhcpScope.start_int).all(),
        manual_form=ManualHostForm(),
    )


def _hosts_query():
    query = NetworkHost.query
    text = (request.args.get("q") or "").strip()
    if text:
        pattern = "%%%s%%" % text.lower()
        query = query.filter(or_(NetworkHost.ip.ilike(pattern),
                                 NetworkHost.hostname.ilike(pattern),
                                 NetworkHost.mac.ilike(pattern)))
    kind = request.args.get("kind", "")
    if kind in classify.KIND_TITLES:
        query = query.filter(NetworkHost.kind == kind)
    scope = request.args.get("scope", "")
    if scope:
        query = query.filter(NetworkHost.scope_id == scope)
    if request.args.get("unlinked"):
        query = query.filter(NetworkHost.ad_computer_id.is_(None))
    return query


@assets_bp.route("/hosts.csv")
@login_required
def hosts_csv():
    rows = []
    for host in _hosts_query().order_by(NetworkHost.ip_int).all():
        computer = host.ad_computer
        rows.append([
            host.ip, host.hostname, host.mac, host.kind_title,
            computer.ou_path if computer else "",
            computer.description if computer else "",
            computer.os if computer else "",
            host.dhcp_server, host.lease_state,
            host.lease_expires_at.strftime("%d.%m.%Y %H:%M")
            if host.lease_expires_at else "",
            host.last_seen.strftime("%d.%m.%Y %H:%M") if host.last_seen else "",
        ])
    return csv_response(
        "uzly-seti",
        ["Адрес", "Имя", "MAC", "Вид", "Подразделение", "Описание", "ОС",
         "Сервер DHCP", "Состояние аренды", "Аренда до", "Последняя выгрузка"],
        rows,
    )


# --- карточка адреса -------------------------------------------------------

@assets_bp.route("/host/<ip>", methods=["GET", "POST"])
@login_required
def host_view(ip: str):
    clean = parse_ip(ip)
    if not clean:
        flash("«%s» не похоже на IP-адрес." % ip, "danger")
        return redirect(url_for("assets.search", q=ip))

    host = NetworkHost.query.filter_by(ip=clean).first()
    notes_form = HostNotesForm(obj=host) if host else HostNotesForm()

    if request.method == "POST":
        if not current_user.is_operator:
            flash("Изменять заметки могут только операторы.", "danger")
            return redirect(url_for("assets.host_view", ip=clean))
        if host is None:
            host = inventory.ensure_host(clean, source=SOURCE_MANUAL)
        if notes_form.validate_on_submit():
            host.notes = (notes_form.notes.data or "").strip()
            db.session.commit()
            flash("Заметка сохранена.", "success")
            return redirect(url_for("assets.host_view", ip=clean))

    scope = inventory.scope_for_ip(clean)
    return render_template(
        "assets/host.html",
        ip=clean,
        host=host,
        computer=host.ad_computer if host else None,
        scope=scope,
        notes_form=notes_form,
        observations=host.observations[:50] if host else [],
        lookups=(AssetLookup.query.filter_by(host_id=host.id)
                 .order_by(AssetLookup.created_at.desc()).limit(10).all()
                 if host else []),
        dhcp_configured=load_dhcp_config().is_configured,
        ad_configured=load_ldap_config().is_configured,
    )


@assets_bp.route("/host/<ip>/refresh", methods=["POST"])
@login_required
def host_refresh(ip: str):
    """Спросить у DHCP и AD, что стоит за адресом прямо сейчас.

    Отдельно от выгрузки: выгрузка идёт по расписанию и к моменту разбора
    инцидента может устареть на сутки, а аренда за это время сменится.
    """
    clean = parse_ip(ip)
    if not clean:
        flash("«%s» не похоже на IP-адрес." % ip, "danger")
        return redirect(url_for("assets.dashboard"))

    try:
        host, summary = _live_lookup(clean)
    except (DhcpError, LdapError) as exc:
        db.session.rollback()
        _log_lookup(clean, "ip", found=False, is_live=True, error=str(exc))
        db.session.commit()
        flash(str(exc), "danger")
        return redirect(url_for("assets.host_view", ip=clean))

    _log_lookup(clean, "ip", found=host is not None, is_live=True,
                result=summary, host=host)
    db.session.commit()
    flash(summary or "По этому адресу ничего не нашлось.",
          "success" if host is not None else "warning")
    return redirect(url_for("assets.host_view", ip=clean))


def _live_lookup(ip: str) -> tuple[NetworkHost | None, str]:
    """Живой запрос в DHCP и AD по одному адресу."""
    scope = inventory.scope_for_ip(ip)
    dhcp_config = load_dhcp_config()
    lease = None
    notes = []

    if dhcp_config.is_configured:
        server = scope.server if scope else dhcp_config.host
        with DhcpClient(dhcp_config) as client:
            lease = client.find_lease(server, ip)
        if lease is None and scope is None:
            notes.append(
                "адрес не попадает ни в одну известную область DHCP — "
                "скорее всего он назначен статически"
            )
    else:
        notes.append("подключение к DHCP не настроено")

    host = None
    if lease is not None:
        host, _ = inventory.upsert_lease(lease, source=SOURCE_DHCP)
        db.session.flush()

    name = short_name(lease.hostname) if lease is not None else ""
    if not name and host is not None:
        name = host.hostname

    ldap_config = load_ldap_config()
    if name and ldap_config.is_configured:
        with LdapClient(ldap_config) as client:
            computer = client.find_computer(name)
        if computer is not None:
            inventory.upsert_computer(computer)
            db.session.flush()
            if host is None:
                host = inventory.ensure_host(ip, source=SOURCE_AD)
                host.hostname = name
            inventory.link_host(host)
        else:
            notes.append("объекта «%s» в Active Directory нет" % name)
    elif name and not ldap_config.is_configured:
        notes.append("подключение к Active Directory не настроено")

    if host is not None:
        host.checked_at = datetime.utcnow()
        host.last_seen = datetime.utcnow()

    summary = _summary(host, notes)
    return host, summary


def _summary(host: NetworkHost | None, notes: list[str]) -> str:
    if host is None:
        text = "Ничего не найдено"
    else:
        parts = [host.display_name or "имя неизвестно", host.kind_title]
        if host.ad_computer is not None and host.ad_computer.ou_path:
            parts.append(host.ad_computer.ou_path)
        text = " · ".join(p for p in parts if p)
    if notes:
        text += " (%s)" % "; ".join(notes)
    return text


@assets_bp.route("/hosts/add", methods=["POST"])
@operator_required
def host_add():
    """Завести адрес вручную — для узлов вне DHCP и вне домена."""
    form = ManualHostForm()
    if not form.validate_on_submit():
        flash("Укажите адрес.", "danger")
        return redirect(url_for("assets.hosts"))
    clean = parse_ip(form.ip.data or "")
    if not clean:
        flash("«%s» не похоже на IP-адрес." % (form.ip.data or ""), "danger")
        return redirect(url_for("assets.hosts"))

    host = inventory.ensure_host(clean, source=SOURCE_MANUAL)
    name = short_name(form.hostname.data or "")
    if name:
        host.hostname = name
        host.kind = classify.classify(name=name)
    if form.notes.data:
        host.notes = form.notes.data.strip()
    host.source = SOURCE_MANUAL
    inventory.link_host(host)
    db.session.commit()
    flash("Адрес %s добавлен." % clean, "success")
    return redirect(url_for("assets.host_view", ip=clean))


# --- компьютеры AD ---------------------------------------------------------

@assets_bp.route("/computers")
@login_required
def computers():
    query = AdComputer.query
    text = (request.args.get("q") or "").strip()
    if text:
        pattern = "%%%s%%" % text.lower()
        query = query.filter(or_(AdComputer.name.ilike(pattern),
                                 AdComputer.description.ilike(pattern),
                                 AdComputer.ou_path.ilike(pattern)))
    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(AdComputer.name).paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )
    return render_template("assets/computers.html", items=pagination.items,
                           pagination=pagination, q=text)


# --- области DHCP ----------------------------------------------------------

@assets_bp.route("/scopes")
@login_required
def scopes():
    rows = DhcpScope.query.order_by(DhcpScope.server, DhcpScope.start_int).all()
    return render_template("assets/scopes.html", items=rows)


# --- журнал ----------------------------------------------------------------

@assets_bp.route("/logs")
@login_required
def logs():
    page = request.args.get("page", 1, type=int)
    pagination = (AssetLookup.query.order_by(AssetLookup.created_at.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    return render_template(
        "assets/logs.html",
        items=pagination.items,
        pagination=pagination,
        syncs=(AssetSyncLog.query.order_by(AssetSyncLog.started_at.desc())
               .limit(20).all()),
    )


# --- выгрузка --------------------------------------------------------------

@assets_bp.route("/sync", methods=["GET", "POST"])
@login_required
def sync():
    form = SyncForm()
    if request.method == "POST":
        if not current_user.is_operator:
            flash("Запускать выгрузку могут только операторы.", "danger")
            return redirect(url_for("assets.sync"))
        if form.submit_dhcp.data:
            return _start_dhcp_sync()
        if form.submit_ad.data:
            return _start_ad_sync()

    return render_template(
        "assets/sync.html",
        form=form,
        dhcp_configured=load_dhcp_config().is_configured,
        ad_configured=load_ldap_config().is_configured,
        servers=target_servers(),
        discover=discover_servers(),
        recent=(AssetSyncLog.query.order_by(AssetSyncLog.started_at.desc())
                .limit(15).all()),
        scopes_count=DhcpScope.query.count(),
    )


def _start_dhcp_sync():
    if not load_dhcp_config().is_configured:
        flash("Сначала настройте подключение к DHCP.", "warning")
        return redirect(url_for("assets.settings"))
    if active_job(JOB_KIND_ASSETS_DHCP) is not None:
        flash("Выгрузка аренд уже идёт — дождитесь её окончания.", "warning")
        return redirect(url_for("assets.sync"))

    start_job(
        current_app._get_current_object(),
        kind=JOB_KIND_ASSETS_DHCP,
        service_id="assets",
        title="Выгрузка аренд DHCP",
        user_id=current_user.id,
        target_url=url_for("assets.hosts"),
        worker=_dhcp_worker(current_user.id),
    )
    flash("Выгрузка аренд запущена в фоне. Можно продолжать работу.", "info")
    return redirect(url_for("assets.sync"))


def _start_ad_sync():
    if not load_ldap_config().is_configured:
        flash("Сначала настройте подключение к Active Directory.", "warning")
        return redirect(url_for("assets.settings"))
    if active_job(JOB_KIND_ASSETS_AD) is not None:
        flash("Выгрузка из AD уже идёт — дождитесь её окончания.", "warning")
        return redirect(url_for("assets.sync"))

    start_job(
        current_app._get_current_object(),
        kind=JOB_KIND_ASSETS_AD,
        service_id="assets",
        title="Выгрузка компьютеров из Active Directory",
        user_id=current_user.id,
        target_url=url_for("assets.computers"),
        worker=_ad_worker(current_user.id),
    )
    flash("Выгрузка из AD запущена в фоне.", "info")
    return redirect(url_for("assets.sync"))


def _open_log(source: str, user_id: int) -> AssetSyncLog:
    log = AssetSyncLog(source=source, user_id=user_id,
                       started_at=datetime.utcnow())
    db.session.add(log)
    db.session.commit()
    return log


def _close_log(log_id: int, *, ok: bool, message: str, **counters) -> None:
    log = db.session.get(AssetSyncLog, log_id)
    if log is None:
        return
    log.finished_at = datetime.utcnow()
    log.ok = ok
    log.message = message[:4000]
    for name, value in counters.items():
        setattr(log, name, value)
    db.session.commit()


def _dhcp_worker(user_id: int):
    """Выгрузить аренды со всех серверов DHCP."""

    def worker(handle):
        config = load_dhcp_config()
        if not config.is_configured:
            raise JobError("Подключение к DHCP не настроено.")

        log = _open_log("dhcp", user_id)
        received = created = updated = scopes_done = 0
        errors: list[str] = []
        failed_servers: list[str] = []

        try:
            with DhcpClient(config) as client:
                servers = target_servers()
                if not servers:
                    handle.progress(detail="Спрашиваем у домена список серверов…")
                    servers = [s.name or s.address for s in client.list_servers()]
                if not servers:
                    raise JobError(
                        "Не задано ни одного сервера DHCP и в домене их не "
                        "нашлось. Укажите сервер в настройках сервиса."
                    )

                # Сначала собираем области всех серверов: так известно общее
                # число шагов, и плашка показывает честный прогресс.
                plan: list[tuple[str, object]] = []
                for server in servers:
                    handle.check()
                    try:
                        for scope in client.list_scopes(server):
                            plan.append((server, scope))
                    except DhcpError as exc:
                        failed_servers.append(server)
                        errors.append("%s: %s" % (server, exc))
                handle.set_total(len(plan) or 1)

                for index, (server, scope) in enumerate(plan, start=1):
                    handle.check()
                    handle.progress(
                        processed=index,
                        detail="%s · область %s" % (server, scope.scope_id),
                    )
                    try:
                        leases = client.list_leases(server, scope.scope_id)
                    except DhcpError as exc:
                        errors.append("%s/%s: %s" % (server, scope.scope_id, exc))
                        continue

                    inventory.upsert_scope(server, scope, lease_count=len(leases))
                    scopes_done += 1
                    for position, lease in enumerate(leases, start=1):
                        received += 1
                        try:
                            _, is_new = inventory.upsert_lease(lease)
                        except ValueError:
                            continue
                        created += 1 if is_new else 0
                        updated += 0 if is_new else 1
                        # Длинная транзакция в SQLite блокирует весь портал.
                        if position % WRITE_BATCH == 0:
                            db.session.commit()
                    db.session.commit()

            handle.progress(detail="Связываем адреса с объектами AD…")
            linked = inventory.link_all()
            db.session.commit()
        except JobError:
            _close_log(log.id, ok=False, message="Выгрузка не выполнена.")
            raise
        except Exception as exc:  # noqa: BLE001 — исполнитель ходит в сеть
            db.session.rollback()
            _close_log(log.id, ok=False, message=str(exc))
            raise

        message = ("Серверов опрошено: %d из %d, областей: %d, аренд получено: "
                   "%d (новых адресов: %d, обновлено: %d), связано с AD: %d."
                   % (len(servers) - len(failed_servers), len(servers),
                      scopes_done, received, created, updated, linked))
        if errors:
            # Раньше сюда сваливались все отказы подряд, и при веере по
            # домену сообщение раздувалось до нескольких тысяч знаков
            # одинаковых строк — полезный итог в нём тонул.
            message += (" Не ответили серверов: %d (%s%s)."
                        % (len(failed_servers), ", ".join(failed_servers[:3]),
                           " и другие" if len(failed_servers) > 3 else ""))
            message += " Первая причина: %s" % errors[0]
        # Частичный сбор — это не провал: аренды, которые удалось прочитать,
        # уже в базе и работают. Провал — когда не собрано вообще ничего.
        _close_log(log.id, ok=bool(received), message=message,
                   servers=len(servers), scopes=scopes_done, received=received,
                   created=created, updated=updated)
        return message

    return worker


def _ad_worker(user_id: int):
    """Выгрузить объекты компьютеров из каталога."""

    def worker(handle):
        config = load_ldap_config()
        if not config.is_configured:
            raise JobError("Подключение к Active Directory не настроено.")

        log = _open_log("ad", user_id)
        received = created = updated = 0
        try:
            handle.progress(detail="Читаем каталог…")
            with LdapClient(config) as client:
                for computer in client.iter_computers():
                    handle.check()
                    received += 1
                    try:
                        _, is_new = inventory.upsert_computer(computer)
                    except ValueError:
                        continue
                    created += 1 if is_new else 0
                    updated += 0 if is_new else 1
                    if received % WRITE_BATCH == 0:
                        db.session.commit()
                        handle.progress(processed=received,
                                        detail="получено объектов: %d" % received)
            db.session.commit()

            handle.progress(detail="Связываем адреса с объектами AD…")
            linked = inventory.link_all()
            db.session.commit()
        except JobError:
            _close_log(log.id, ok=False, message="Выгрузка не выполнена.")
            raise
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            _close_log(log.id, ok=False, message=str(exc))
            raise

        message = ("Объектов получено: %d (новых: %d, обновлено: %d), "
                   "связано с адресами: %d." % (received, created, updated, linked))
        _close_log(log.id, ok=True, message=message, received=received,
                   created=created, updated=updated)
        return message

    return worker


# --- настройки -------------------------------------------------------------

@assets_bp.route("/settings", methods=["GET", "POST"])
@operator_required
def settings():
    ad_form = _ad_form()
    dhcp_form = _dhcp_form()

    def _render():
        return render_template(
            "assets/settings.html",
            ad_form=ad_form,
            dhcp_form=dhcp_form,
            ad_password_set=bool(get_setting(KEY_AD_PASSWORD)),
            dhcp_password_set=bool(get_setting(KEY_DHCP_PASSWORD)),
            default_ad_port=DEFAULT_AD_PORT,
            default_dhcp_port=DEFAULT_DHCP_PORT,
        )

    if (ad_form.submit_ad.data or ad_form.test_ad.data) \
            and ad_form.validate_on_submit():
        _save_ad(ad_form)
        db.session.commit()
        if ad_form.test_ad.data:
            _test_ad()
            return _render()
        flash("Настройки Active Directory сохранены.", "success")
        return redirect(url_for("assets.settings"))

    if (dhcp_form.submit_dhcp.data or dhcp_form.test_dhcp.data) \
            and dhcp_form.validate_on_submit():
        _save_dhcp(dhcp_form)
        db.session.commit()
        if dhcp_form.test_dhcp.data:
            _test_dhcp()
            return _render()
        flash("Настройки DHCP сохранены.", "success")
        return redirect(url_for("assets.settings"))

    return _render()


def _ad_form() -> AdSettingsForm:
    form = AdSettingsForm()
    if request.method == "GET":
        form.host.data = get_setting(KEY_AD_HOST, "")
        form.port.data = int(get_setting(KEY_AD_PORT, "") or DEFAULT_AD_PORT)
        form.use_ssl.data = get_setting(KEY_AD_SSL, "") == "1"
        form.domain.data = get_setting(KEY_AD_DOMAIN, "")
        form.base_dn.data = get_setting(KEY_AD_BASE_DN, "")
        form.username.data = get_setting(KEY_AD_USER, "")
        form.timeout.data = int(get_setting(KEY_AD_TIMEOUT, "")
                                or DEFAULT_AD_TIMEOUT)
    return form


def _dhcp_form() -> DhcpSettingsForm:
    form = DhcpSettingsForm()
    if request.method == "GET":
        form.host.data = get_setting(KEY_DHCP_HOST, "")
        form.port.data = int(get_setting(KEY_DHCP_PORT, "") or DEFAULT_DHCP_PORT)
        form.use_ssl.data = get_setting(KEY_DHCP_SSL, "") == "1"
        form.username.data = get_setting(KEY_DHCP_USER, "")
        form.timeout.data = int(get_setting(KEY_DHCP_TIMEOUT, "")
                                or DEFAULT_DHCP_TIMEOUT)
        form.discover.data = get_setting(KEY_DHCP_DISCOVER, "") == "1"
        form.servers.data = get_setting(KEY_DHCP_SERVERS, "")
    return form


def _save_ad(form) -> None:
    set_setting(KEY_AD_HOST, (form.host.data or "").strip())
    set_setting(KEY_AD_PORT, str(form.port.data or DEFAULT_AD_PORT))
    set_setting(KEY_AD_SSL, "1" if form.use_ssl.data else "0")
    set_setting(KEY_AD_DOMAIN, (form.domain.data or "").strip())
    set_setting(KEY_AD_BASE_DN, (form.base_dn.data or "").strip())
    set_setting(KEY_AD_USER, (form.username.data or "").strip())
    set_setting(KEY_AD_TIMEOUT, str(form.timeout.data or DEFAULT_AD_TIMEOUT))
    # Пароль перезаписываем, только если его ввели заново.
    if form.password.data:
        set_setting(KEY_AD_PASSWORD, form.password.data, is_secret=True)


def _save_dhcp(form) -> None:
    set_setting(KEY_DHCP_HOST, (form.host.data or "").strip())
    set_setting(KEY_DHCP_PORT, str(form.port.data or DEFAULT_DHCP_PORT))
    set_setting(KEY_DHCP_SSL, "1" if form.use_ssl.data else "0")
    set_setting(KEY_DHCP_USER, (form.username.data or "").strip())
    set_setting(KEY_DHCP_TIMEOUT, str(form.timeout.data or DEFAULT_DHCP_TIMEOUT))
    set_setting(KEY_DHCP_DISCOVER, "1" if form.discover.data else "0")
    set_setting(KEY_DHCP_SERVERS, (form.servers.data or "").strip())
    if form.password.data:
        set_setting(KEY_DHCP_PASSWORD, form.password.data, is_secret=True)


def _test_ad() -> None:
    """Проверить вход в каталог и что база поиска действительно отвечает.

    Одного успешного бинда мало: он проходит и при неверной базе поиска, а
    тогда любой запрос вернёт пусто, и оператор будет искать причину в правах.
    Поэтому делаем ещё и настоящий поиск.
    """
    config = load_ldap_config()
    if not config.is_configured:
        flash("Заполните контроллер, учётную запись и пароль.", "warning")
        return
    try:
        with LdapClient(config) as client:
            found = client.search_computers("a", limit=5)
    except LdapError as exc:
        flash("Active Directory: %s" % exc, "danger")
        return
    if not found:
        flash("Вход выполнен, но по базе «%s» не нашлось ни одного компьютера. "
              "Проверьте базу поиска — обычно это DC=домен,DC=local."
              % (config.base_dn or "не задана"), "warning")
        return
    flash("Active Directory отвечает: пробный поиск вернул объекты (%s…)."
          % found[0].name, "success")


def _test_dhcp() -> None:
    config = load_dhcp_config()
    if not config.is_configured:
        flash("Заполните сервер, учётную запись и пароль.", "warning")
        return
    try:
        with DhcpClient(config) as client:
            servers = client.list_servers()
    except DhcpError as exc:
        flash("DHCP: %s" % exc, "danger")
        return
    if not servers:
        flash("Связь есть, но список серверов DHCP пуст. Возможно, учётной "
              "записи не хватает прав на чтение.", "warning")
        return
    flash("Связь с DHCP есть. Серверов в домене: %d (%s%s)."
          % (len(servers), ", ".join(s.name for s in servers[:5]),
             "…" if len(servers) > 5 else ""), "success")
