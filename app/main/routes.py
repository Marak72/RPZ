"""Основные маршруты: дашборд, RPZ, кандидаты по категориям, URL, IoC,
выгрузка на боевой DNS-сервер, экспорт CSV и настройки."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from functools import wraps

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from ..extensions import db
from ..models import (
    PUSH_DRY_RUN,
    STATUS_IN_RPZ,
    STATUS_NEW,
    STATUS_PUSHED,
    BlockEntry,
    Document,
    IocHash,
    PushLog,
    RpzEntry,
    RpzSnapshot,
    SshServer,
    UrlEntry,
)
from ..services import doc_parser, rpz_parser, rpz_writer
from ..services.rpz_writer import PushError
from ..services.ssh_client import SshError, read_remote_file, test_connection
from .forms import SshServerForm, UploadForm

main_bp = Blueprint("main", __name__)

# Типы записей, которые являются хешами (а не адресами для блокировки).
HASH_TYPES = ("sha256", "sha1", "md5")
PER_PAGE = 100


def operator_required(view):
    """Доступ только для операторов; менеджеры — только просмотр."""

    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_operator:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _latest_snapshot() -> RpzSnapshot | None:
    return RpzSnapshot.query.order_by(RpzSnapshot.fetched_at.desc()).first()


def _latest_blocked_domains() -> set[str]:
    """Множество доменов из последнего снимка RPZ для сверки кандидатов."""
    snap = _latest_snapshot()
    if not snap:
        return set()
    return {e.domain for e in snap.entries}


def _active_server() -> SshServer | None:
    return SshServer.query.filter_by(is_active=True).first()


def _csv_response(filename: str, header: list[str], rows) -> Response:
    """Сформировать CSV-файл (разделитель ';' и BOM — корректно открывается в Excel)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", quoting=csv.QUOTE_MINIMAL,
                        lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows(rows)
    data = "﻿" + buffer.getvalue()
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}-{stamp}.csv"'
        },
    )


def _fmt(value) -> str:
    return value.strftime("%d.%m.%Y %H:%M") if value else ""


# --- Дашборд --------------------------------------------------------------

@main_bp.route("/")
@login_required
def dashboard():
    snap = _latest_snapshot()
    blocked = _latest_blocked_domains()

    domains_q = BlockEntry.query.filter_by(entry_type="domain")
    stats = {
        "rpz_domains": len(blocked),
        "rpz_records": snap.entry_count if snap else 0,
        "documents": Document.query.count(),
        "domains": domains_q.count(),
        "ips": BlockEntry.query.filter_by(entry_type="ip").count(),
        "urls": UrlEntry.query.count(),
        "hashes": IocHash.query.count(),
        "pending": domains_q.filter(BlockEntry.status == STATUS_NEW).count(),
        "pushed": domains_q.filter(BlockEntry.status == STATUS_PUSHED).count(),
    }

    recent_docs = (
        Document.query.order_by(Document.uploaded_at.desc()).limit(5).all()
    )
    recent_pushes = (
        PushLog.query.order_by(PushLog.started_at.desc()).limit(5).all()
    )
    return render_template(
        "dashboard.html",
        snapshot=snap,
        stats=stats,
        recent_docs=recent_docs,
        recent_pushes=recent_pushes,
        server=_active_server(),
    )


# --- Просмотр RPZ ---------------------------------------------------------

def _snapshot_rows(snap: RpzSnapshot | None) -> list[dict]:
    if not snap:
        return []
    entries = [
        rpz_parser.ParsedEntry(
            domain=e.domain,
            is_wildcard=e.is_wildcard,
            record_type=e.record_type,
            target=e.target,
            action=e.action,
        )
        for e in snap.entries
    ]
    return rpz_parser.group_by_domain(entries)


@main_bp.route("/rpz")
@login_required
def rpz_view():
    snap = _latest_snapshot()
    rows = _snapshot_rows(snap)

    q = request.args.get("q", "").strip().lower()
    action = request.args.get("action", "").strip()
    if q:
        rows = [r for r in rows if q in r["domain"]]
    if action:
        rows = [r for r in rows if r["action"] == action]

    blocked_total = len(_snapshot_rows(snap))
    return render_template(
        "rpz_view.html",
        snapshot=snap,
        rows=rows,
        q=q,
        action=action,
        server=_active_server(),
        blocked_total=blocked_total,
    )


@main_bp.route("/rpz.csv")
@login_required
def rpz_csv():
    rows = _snapshot_rows(_latest_snapshot())
    return _csv_response(
        "rpz-blocked",
        ["Домен", "Тип записи", "Действие", "Цель", "Wildcard"],
        [
            [r["domain"], r["record_type"], r["action"], r["target"],
             "да" if r["has_wildcard"] else "нет"]
            for r in rows
        ],
    )


@main_bp.route("/rpz/refresh", methods=["POST"])
@operator_required
def rpz_refresh():
    server = _active_server()
    if not server:
        flash("Сначала настройте учётную запись SSH в разделе «Настройки».", "warning")
        return redirect(url_for("main.settings"))

    try:
        content = read_remote_file(server, timeout=current_app.config["SSH_TIMEOUT"])
    except (SshError, RuntimeError) as exc:
        flash(str(exc), "danger")
        return redirect(url_for("main.rpz_view"))
    except Exception as exc:  # noqa: BLE001 — не показывать пользователю трассировку
        current_app.logger.exception("Ошибка чтения зоны по SSH")
        flash(f"Непредвиденная ошибка при чтении зоны: {exc}", "danger")
        return redirect(url_for("main.rpz_view"))

    parsed = rpz_parser.parse(content)
    if not parsed:
        flash(
            "Файл зоны прочитан, но записей блокировки в нём не найдено. "
            "Проверьте путь к файлу в настройках.",
            "warning",
        )

    snap = RpzSnapshot(
        server_id=server.id,
        fetched_by=current_user.id,
        raw_content=content,
        entry_count=len(parsed),
    )
    db.session.add(snap)
    db.session.flush()
    for e in parsed:
        db.session.add(
            RpzEntry(
                snapshot_id=snap.id,
                domain=e.domain,
                is_wildcard=e.is_wildcard,
                record_type=e.record_type,
                target=e.target,
                action=e.action,
            )
        )

    # Синхронизировать статусы кандидатов с фактическим состоянием зоны.
    blocked = {e.domain for e in parsed}
    for cand in BlockEntry.query.filter_by(entry_type="domain").all():
        if cand.value in blocked and cand.status == STATUS_NEW:
            cand.status = STATUS_IN_RPZ

    db.session.commit()
    flash(f"Файл RPZ считан: {len(parsed)} записей, {len(blocked)} доменов.", "success")
    return redirect(url_for("main.rpz_view"))


@main_bp.route("/rpz/history")
@login_required
def rpz_history():
    snapshots = RpzSnapshot.query.order_by(RpzSnapshot.fetched_at.desc()).all()
    return render_template("rpz_history.html", snapshots=snapshots)


@main_bp.route("/rpz/history/<int:snapshot_id>")
@login_required
def rpz_snapshot_view(snapshot_id: int):
    snap = db.session.get(RpzSnapshot, snapshot_id)
    if not snap:
        abort(404)
    return render_template("rpz_snapshot.html", snapshot=snap,
                           rows=_snapshot_rows(snap))


# --- Загрузка и разбор писем ФСТЭК ----------------------------------------

def _split_extracted(extracted) -> dict:
    """Разложить результат парсера по категориям с отметками о наличии в базе."""
    existing = {b.value for b in BlockEntry.query.all()}
    existing_urls = {u.value for u in UrlEntry.query.all()}
    existing_hashes = {h.value for h in IocHash.query.all()}
    blocked = _latest_blocked_domains()

    domains, ips, urls, hashes = [], [], [], []
    for e in extracted:
        if e.entry_type == "domain":
            domains.append({
                "value": e.value, "type": "domain",
                "already_in_db": e.value in existing,
                "in_rpz": e.value in blocked,
            })
        elif e.entry_type == "ip":
            ips.append({
                "value": e.value, "type": "ip",
                "already_in_db": e.value in existing,
                "in_rpz": False,
            })
        elif e.entry_type == "url":
            urls.append({
                "value": e.value, "host": e.host,
                "already_in_db": e.value in existing_urls,
            })
        elif e.entry_type in HASH_TYPES:
            hashes.append({
                "value": e.value, "type": e.entry_type,
                "already_in_db": e.value in existing_hashes,
            })
    return {"domains": domains, "ips": ips, "urls": urls, "hashes": hashes}


@main_bp.route("/upload", methods=["GET", "POST"])
@operator_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.document.data
        try:
            data = file.read()
            extracted = doc_parser.extract_from_file(file.filename, data)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("main.upload"))
        except Exception as exc:  # noqa: BLE001 — повреждённый документ и т.п.
            current_app.logger.exception("Ошибка разбора письма")
            flash(
                f"Не удалось разобрать файл «{file.filename}»: {exc}. "
                "Убедитесь, что это корректный .docx или .odt.",
                "danger",
            )
            return redirect(url_for("main.upload"))

        groups = _split_extracted(extracted)
        total = sum(len(v) for v in groups.values())
        if total == 0:
            flash(
                "В документе не найдено ни одного индикатора. "
                "Возможно, индикаторы приведены в приложении к письму отдельным файлом.",
                "warning",
            )
            return redirect(url_for("main.upload"))

        return render_template(
            "preview.html",
            groups=groups,
            filename=file.filename,
            notes=form.notes.data or "",
            total=total,
        )
    return render_template("upload.html", form=form)


@main_bp.route("/preview/csv", methods=["POST"])
@operator_required
def preview_csv():
    """Скачать CSV прямо из предпросмотра распознанного письма."""
    rows = []
    for value in request.form.getlist("all_domain"):
        rows.append(["домен", value, ""])
    for value in request.form.getlist("all_ip"):
        rows.append(["IP", value, ""])
    for value in request.form.getlist("all_url"):
        rows.append(["URL (с путём)", value, ""])
    for value in request.form.getlist("all_hash"):
        rows.append(["хеш", value, request.form.get(f"htype_{value}", "")])
    if not rows:
        flash("Нечего экспортировать.", "warning")
        return redirect(url_for("main.upload"))
    return _csv_response("fstec-parsed", ["Категория", "Значение", "Тип"], rows)


@main_bp.route("/preview", methods=["POST"])
@operator_required
def preview_save():
    selected = request.form.getlist("selected")
    selected_urls = request.form.getlist("selected_url")
    selected_hashes = request.form.getlist("selected_hash")
    filename = request.form.get("filename", "письмо")
    notes = request.form.get("notes", "")

    if not (selected or selected_urls or selected_hashes):
        flash("Не выбрано ни одной записи для сохранения.", "warning")
        return redirect(url_for("main.upload"))

    blocked = _latest_blocked_domains()
    existing = {b.value for b in BlockEntry.query.all()}
    existing_urls = {u.value for u in UrlEntry.query.all()}
    existing_hashes = {h.value for h in IocHash.query.all()}

    doc = Document(filename=filename, uploaded_by=current_user.id, notes=notes)
    db.session.add(doc)
    db.session.flush()

    added = 0
    for value in selected:
        value = value.strip().lower()
        if not value or value in existing:
            continue
        is_ip = doc_parser._valid_ipv4(value)
        # Не сохраняем мусор: домен обязан пройти строгую валидацию.
        if not is_ip and not doc_parser.is_valid_domain(value):
            continue
        db.session.add(
            BlockEntry(
                value=value,
                entry_type="ip" if is_ip else "domain",
                document_id=doc.id,
                status=STATUS_IN_RPZ if value in blocked else STATUS_NEW,
                added_by=current_user.id,
            )
        )
        existing.add(value)
        added += 1

    urls_added = 0
    for value in selected_urls:
        value = value.strip()
        if not value or value in existing_urls:
            continue
        parsed = doc_parser._parse_url(value)
        host = parsed[0] if parsed else ""
        db.session.add(
            UrlEntry(value=value, host=host, document_id=doc.id,
                     added_by=current_user.id)
        )
        existing_urls.add(value)
        urls_added += 1

    hashes_added = 0
    for value in selected_hashes:
        value = value.strip().lower()
        if not value or value in existing_hashes:
            continue
        db.session.add(
            IocHash(
                value=value,
                hash_type=_hash_type_of(value),
                document_id=doc.id,
                added_by=current_user.id,
            )
        )
        existing_hashes.add(value)
        hashes_added += 1

    doc.entries_found = added + urls_added + hashes_added
    try:
        db.session.commit()
    except Exception as exc:  # noqa: BLE001 — например, гонка по уникальному индексу
        db.session.rollback()
        current_app.logger.exception("Ошибка сохранения индикаторов")
        flash(f"Не удалось сохранить записи: {exc}", "danger")
        return redirect(url_for("main.upload"))

    flash(
        f"Сохранено: адресов — {added}, URL — {urls_added}, хешей — {hashes_added}.",
        "success",
    )
    return redirect(url_for("main.candidates"))


def _hash_type_of(value: str) -> str:
    return {64: "sha256", 40: "sha1", 32: "md5"}.get(len(value), "sha256")


# --- Кандидаты (домены и IP) ----------------------------------------------

def _candidates_query():
    q = request.args.get("q", "").strip().lower()
    status = request.args.get("status", "").strip()
    etype = request.args.get("type", "").strip()
    query = BlockEntry.query
    if q:
        query = query.filter(BlockEntry.value.like(f"%{q}%"))
    if status:
        query = query.filter_by(status=status)
    if etype:
        query = query.filter_by(entry_type=etype)
    return query.order_by(BlockEntry.created_at.desc()), q, status, etype


@main_bp.route("/candidates")
@login_required
def candidates():
    query, q, status, etype = _candidates_query()
    page = request.args.get("page", 1, type=int)
    pagination = query.paginate(page=page, per_page=PER_PAGE, error_out=False)
    counts = {
        "all": BlockEntry.query.count(),
        "domain": BlockEntry.query.filter_by(entry_type="domain").count(),
        "ip": BlockEntry.query.filter_by(entry_type="ip").count(),
    }
    return render_template(
        "candidates.html",
        pagination=pagination,
        items=pagination.items,
        q=q,
        status=status,
        etype=etype,
        counts=counts,
    )


@main_bp.route("/candidates.csv")
@login_required
def candidates_csv():
    query, *_ = _candidates_query()
    return _csv_response(
        "fstec-candidates",
        ["Значение", "Тип", "Статус", "Источник", "Добавлен", "Выгружен"],
        [
            [
                it.value, it.entry_type, it.status,
                it.document.filename if it.document else "",
                _fmt(it.created_at), _fmt(it.pushed_at),
            ]
            for it in query.all()
        ],
    )


# --- URL с путями ----------------------------------------------------------

@main_bp.route("/urls")
@login_required
def urls():
    q = request.args.get("q", "").strip().lower()
    query = UrlEntry.query
    if q:
        query = query.filter(UrlEntry.value.like(f"%{q}%"))
    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(UrlEntry.created_at.desc()).paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )
    return render_template(
        "urls.html", pagination=pagination, items=pagination.items, q=q
    )


@main_bp.route("/urls.csv")
@login_required
def urls_csv():
    items = UrlEntry.query.order_by(UrlEntry.created_at.desc()).all()
    return _csv_response(
        "fstec-urls",
        ["URL", "Хост", "Источник", "Добавлен"],
        [
            [it.value, it.host, it.document.filename if it.document else "",
             _fmt(it.created_at)]
            for it in items
        ],
    )


# --- Хеши (IoC) ------------------------------------------------------------

def _iocs_query():
    q = request.args.get("q", "").strip().lower()
    htype = request.args.get("type", "").strip()
    query = IocHash.query
    if q:
        query = query.filter(IocHash.value.like(f"%{q}%"))
    if htype:
        query = query.filter_by(hash_type=htype)
    return query.order_by(IocHash.created_at.desc()), q, htype


@main_bp.route("/iocs")
@login_required
def iocs():
    query, q, htype = _iocs_query()
    page = request.args.get("page", 1, type=int)
    pagination = query.paginate(page=page, per_page=PER_PAGE, error_out=False)
    counts = {t: IocHash.query.filter_by(hash_type=t).count() for t in HASH_TYPES}
    return render_template(
        "iocs.html", pagination=pagination, items=pagination.items,
        q=q, htype=htype, counts=counts,
    )


@main_bp.route("/iocs.csv")
@login_required
def iocs_csv():
    query, *_ = _iocs_query()
    return _csv_response(
        "fstec-hashes",
        ["Хеш", "Тип", "Источник", "Добавлен"],
        [
            [it.value, it.hash_type, it.document.filename if it.document else "",
             _fmt(it.created_at)]
            for it in query.all()
        ],
    )


# --- Выгрузка на боевой DNS-сервер ----------------------------------------

@main_bp.route("/push")
@login_required
def push_view():
    """Экран выбора доменов для выгрузки: видно, что уже в RPZ, а что нет."""
    blocked = _latest_blocked_domains()
    domains = (
        BlockEntry.query.filter_by(entry_type="domain")
        .order_by(BlockEntry.created_at.desc())
        .all()
    )
    rows = []
    for d in domains:
        in_rpz = d.value in blocked
        rows.append({
            "value": d.value,
            "status": d.status,
            "in_rpz": in_rpz,
            "pushed_at": d.pushed_at,
            "document": d.document.filename if d.document else "",
            "created_at": d.created_at,
        })
    pending = [r for r in rows if not r["in_rpz"]]
    snap = _latest_snapshot()
    return render_template(
        "push.html",
        rows=rows,
        pending_count=len(pending),
        server=_active_server(),
        snapshot=snap,
        ip_count=BlockEntry.query.filter_by(entry_type="ip").count(),
    )


@main_bp.route("/push", methods=["POST"])
@operator_required
def push_run():
    """Выгрузить выбранные домены в RPZ-зону (или показать предпросмотр)."""
    selected = [v.strip().lower() for v in request.form.getlist("domains") if v.strip()]
    dry_run = bool(request.form.get("dry_run"))

    server = _active_server()
    if not server:
        flash("Сначала настройте учётную запись SSH в разделе «Настройки».", "warning")
        return redirect(url_for("main.settings"))
    if not selected:
        flash("Не выбрано ни одного домена для выгрузки.", "warning")
        return redirect(url_for("main.push_view"))

    log = PushLog(
        server_id=server.id,
        user_id=current_user.id,
        status="failed",
        entries_count=0,
    )
    try:
        result = rpz_writer.push_domains(
            server,
            selected,
            timeout=current_app.config["SSH_TIMEOUT"],
            dry_run=dry_run,
            author=current_user.username,
        )
    except (PushError, SshError, RuntimeError) as exc:
        log.status = "failed"
        log.message = str(exc)
        log.domains = ", ".join(selected)
        log.finished_at = datetime.utcnow()
        db.session.add(log)
        db.session.commit()
        flash(f"Выгрузка не выполнена: {exc}", "danger")
        return redirect(url_for("main.push_log_view", log_id=log.id))
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Непредвиденная ошибка выгрузки")
        log.status = "failed"
        log.message = f"Непредвиденная ошибка: {exc}"
        log.domains = ", ".join(selected)
        log.finished_at = datetime.utcnow()
        db.session.add(log)
        db.session.commit()
        flash(f"Непредвиденная ошибка при выгрузке: {exc}", "danger")
        return redirect(url_for("main.push_log_view", log_id=log.id))

    log.status = result.status
    log.entries_count = len(result.added)
    log.domains = ", ".join(result.added)
    log.backup_path = result.backup_path
    log.old_serial = result.old_serial
    log.new_serial = result.new_serial
    log.message = result.log_text
    log.finished_at = datetime.utcnow()
    db.session.add(log)

    if result.status == "success" and result.added:
        now = datetime.utcnow()
        for entry in BlockEntry.query.filter(BlockEntry.value.in_(result.added)).all():
            entry.status = STATUS_PUSHED
            entry.pushed_at = now
    db.session.commit()

    if result.status == PUSH_DRY_RUN:
        flash(
            f"Предпросмотр: будет добавлено {len(result.added)} доменов, "
            f"пропущено (уже в зоне) — {len(result.skipped)}. Файл не изменялся.",
            "info",
        )
    elif result.added:
        flash(
            f"Выгружено доменов: {len(result.added)}. Зона перезагружена, "
            f"serial {result.old_serial} → {result.new_serial}.",
            "success",
        )
    else:
        flash("Все выбранные домены уже присутствуют в зоне — изменений нет.", "info")

    return redirect(url_for("main.push_log_view", log_id=log.id))


@main_bp.route("/push/history")
@login_required
def push_history():
    logs = PushLog.query.order_by(PushLog.started_at.desc()).all()
    return render_template("push_history.html", logs=logs)


@main_bp.route("/push/history/<int:log_id>")
@login_required
def push_log_view(log_id: int):
    log = db.session.get(PushLog, log_id)
    if not log:
        abort(404)
    return render_template("push_log.html", log=log)


# --- Настройки SSH (УЗ) ---------------------------------------------------

def _apply_server_form(form, server) -> None:
    server.name = form.name.data
    server.host = form.host.data
    server.port = form.port.data
    server.username = form.username.data
    server.zone_file_path = form.zone_file_path.data
    server.zone_name = form.zone_name.data
    server.use_sudo = form.use_sudo.data
    server.validate_zone = form.validate_zone.data
    server.reload_zone = form.reload_zone.data
    server.is_active = form.is_active.data


@main_bp.route("/settings", methods=["GET", "POST"])
@operator_required
def settings():
    from ..crypto import encrypt

    server = _active_server()
    form = SshServerForm(obj=server)

    if form.validate_on_submit():
        is_new = server is None
        if is_new and not form.password.data:
            flash("Укажите пароль SSH.", "danger")
            return render_template("settings.html", form=form, server=server)

        # Кнопка «Проверить подключение»: тест на временном объекте, без записи в БД.
        if form.test.data:
            probe = SshServer(password_enc=(
                encrypt(form.password.data) if form.password.data
                else (server.password_enc if server else "")
            ))
            _apply_server_form(form, probe)
            try:
                checks = test_connection(
                    probe, timeout=current_app.config["SSH_TIMEOUT"]
                )
                details = "; ".join(f"{k}: {v}" for k, v in checks.items())
                flash(f"Подключение успешно. {details}", "success")
            except (SshError, RuntimeError) as exc:
                flash(str(exc), "danger")
            except Exception as exc:  # noqa: BLE001
                current_app.logger.exception("Ошибка проверки SSH")
                flash(f"Непредвиденная ошибка проверки: {exc}", "danger")
            return render_template("settings.html", form=form, server=server)

        if is_new:
            server = SshServer()
            db.session.add(server)
        _apply_server_form(form, server)
        if form.password.data:
            server.password_enc = encrypt(form.password.data)
        db.session.commit()
        flash("Настройки SSH сохранены.", "success")
        return redirect(url_for("main.settings"))

    return render_template("settings.html", form=form, server=server)
