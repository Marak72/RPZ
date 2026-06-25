"""Основные маршруты: дашборд, просмотр RPZ, парсер писем, настройки."""
from __future__ import annotations

from functools import wraps

from flask import (
    Blueprint,
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
    STATUS_IN_RPZ,
    STATUS_NEW,
    BlockEntry,
    Document,
    IocHash,
    RpzEntry,
    RpzSnapshot,
    SshServer,
)

# Типы записей, которые являются хешами (а не адресами для блокировки).
HASH_TYPES = ("sha256", "sha1", "md5")
from ..services import doc_parser, rpz_parser
from ..services.ssh_client import SshError, read_remote_file, test_connection
from .forms import SshServerForm, UploadForm

main_bp = Blueprint("main", __name__)


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


# --- Дашборд --------------------------------------------------------------

@main_bp.route("/")
@login_required
def dashboard():
    snap = _latest_snapshot()
    blocked_count = snap.entry_count if snap else 0
    documents_count = Document.query.count()
    candidates_total = BlockEntry.query.count()
    pending_count = BlockEntry.query.filter_by(status=STATUS_NEW).count()
    hashes_count = IocHash.query.count()
    return render_template(
        "dashboard.html",
        snapshot=snap,
        blocked_count=blocked_count,
        documents_count=documents_count,
        candidates_total=candidates_total,
        pending_count=pending_count,
        hashes_count=hashes_count,
    )


# --- Просмотр RPZ ---------------------------------------------------------

@main_bp.route("/rpz")
@login_required
def rpz_view():
    snap = _latest_snapshot()
    rows: list[dict] = []
    if snap:
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
        rows = rpz_parser.group_by_domain(entries)

    q = request.args.get("q", "").strip().lower()
    action = request.args.get("action", "").strip()
    if q:
        rows = [r for r in rows if q in r["domain"]]
    if action:
        rows = [r for r in rows if r["action"] == action]

    server = SshServer.query.filter_by(is_active=True).first()
    return render_template(
        "rpz_view.html",
        snapshot=snap,
        rows=rows,
        q=q,
        action=action,
        server=server,
    )


@main_bp.route("/rpz/refresh", methods=["POST"])
@operator_required
def rpz_refresh():
    server = SshServer.query.filter_by(is_active=True).first()
    if not server:
        flash("Сначала настройте учётную запись SSH в разделе «Настройки».", "warning")
        return redirect(url_for("main.settings"))

    try:
        content = read_remote_file(server, timeout=current_app.config["SSH_TIMEOUT"])
    except SshError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("main.rpz_view"))

    parsed = rpz_parser.parse(content)
    snap = RpzSnapshot(
        server_id=server.id,
        fetched_by=current_user.id,
        raw_content=content,
        entry_count=len(parsed),
    )
    db.session.add(snap)
    db.session.flush()  # получить snap.id
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

    # Обновить статусы кандидатов, которые теперь присутствуют в RPZ.
    blocked = {e.domain for e in parsed}
    for cand in BlockEntry.query.filter_by(entry_type="domain").all():
        if cand.value in blocked and cand.status != STATUS_IN_RPZ:
            cand.status = STATUS_IN_RPZ

    db.session.commit()
    flash(f"Файл RPZ считан: {len(parsed)} записей.", "success")
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
    rows = rpz_parser.group_by_domain(entries)
    return render_template("rpz_snapshot.html", snapshot=snap, rows=rows)


# --- Парсер писем ФСТЭК ---------------------------------------------------

@main_bp.route("/upload", methods=["GET", "POST"])
@operator_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.document.data
        data = file.read()
        try:
            extracted = doc_parser.extract_from_file(file.filename, data)
        except Exception as exc:  # noqa: BLE001 - показать пользователю причину
            flash(f"Не удалось разобрать файл: {exc}", "danger")
            return redirect(url_for("main.upload"))

        existing = {b.value for b in BlockEntry.query.all()}
        existing_hashes = {h.value for h in IocHash.query.all()}
        blocked = _latest_blocked_domains()
        items, hash_items = [], []
        for e in extracted:
            if e.entry_type in HASH_TYPES:
                hash_items.append(
                    {
                        "value": e.value,
                        "type": e.entry_type,
                        "already_in_db": e.value in existing_hashes,
                    }
                )
            else:
                items.append(
                    {
                        "value": e.value,
                        "type": e.entry_type,
                        "already_in_db": e.value in existing,
                        "in_rpz": e.value in blocked,
                    }
                )
        return render_template(
            "preview.html",
            items=items,
            hash_items=hash_items,
            filename=file.filename,
            notes=form.notes.data or "",
        )
    return render_template("upload.html", form=form)


@main_bp.route("/preview", methods=["POST"])
@operator_required
def preview_save():
    selected = request.form.getlist("selected")
    selected_hashes = request.form.getlist("selected_hash")
    filename = request.form.get("filename", "письмо")
    notes = request.form.get("notes", "")
    if not selected and not selected_hashes:
        flash("Не выбрано ни одной записи для сохранения.", "warning")
        return redirect(url_for("main.upload"))

    blocked = _latest_blocked_domains()
    existing = {b.value for b in BlockEntry.query.all()}
    existing_hashes = {h.value for h in IocHash.query.all()}

    doc = Document(
        filename=filename,
        uploaded_by=current_user.id,
        notes=notes,
    )
    db.session.add(doc)
    db.session.flush()

    added = 0
    for value in selected:
        value = value.strip().lower()
        if not value or value in existing:
            continue
        entry_type = "ip" if doc_parser._valid_ipv4(value) else "domain"
        status = STATUS_IN_RPZ if value in blocked else STATUS_NEW
        db.session.add(
            BlockEntry(
                value=value,
                entry_type=entry_type,
                document_id=doc.id,
                status=status,
                added_by=current_user.id,
            )
        )
        existing.add(value)
        added += 1

    hashes_added = 0
    for value in selected_hashes:
        value = value.strip().lower()
        if not value or value in existing_hashes:
            continue
        hash_type = _hash_type_of(value)
        db.session.add(
            IocHash(
                value=value,
                hash_type=hash_type,
                document_id=doc.id,
                added_by=current_user.id,
            )
        )
        existing_hashes.add(value)
        hashes_added += 1

    doc.entries_found = added + hashes_added
    db.session.commit()
    flash(
        f"Сохранено: адресов — {added}, хешей — {hashes_added}.", "success"
    )
    if added and not hashes_added:
        return redirect(url_for("main.candidates"))
    if hashes_added and not added:
        return redirect(url_for("main.iocs"))
    return redirect(url_for("main.candidates"))


def _hash_type_of(value: str) -> str:
    return {64: "sha256", 40: "sha1", 32: "md5"}.get(len(value), "sha256")


@main_bp.route("/candidates")
@login_required
def candidates():
    q = request.args.get("q", "").strip().lower()
    status = request.args.get("status", "").strip()
    query = BlockEntry.query
    if q:
        query = query.filter(BlockEntry.value.like(f"%{q}%"))
    if status:
        query = query.filter_by(status=status)
    items = query.order_by(BlockEntry.created_at.desc()).all()
    return render_template("candidates.html", items=items, q=q, status=status)


@main_bp.route("/iocs")
@login_required
def iocs():
    q = request.args.get("q", "").strip().lower()
    htype = request.args.get("type", "").strip()
    query = IocHash.query
    if q:
        query = query.filter(IocHash.value.like(f"%{q}%"))
    if htype:
        query = query.filter_by(hash_type=htype)
    items = query.order_by(IocHash.created_at.desc()).all()
    return render_template("iocs.html", items=items, q=q, htype=htype)


# --- Настройки SSH (УЗ) ---------------------------------------------------

@main_bp.route("/settings", methods=["GET", "POST"])
@operator_required
def settings():
    from ..crypto import encrypt

    server = SshServer.query.filter_by(is_active=True).first()
    form = SshServerForm(obj=server)

    if form.validate_on_submit():
        is_new = server is None
        # Пароль обязателен только при создании новой УЗ.
        if is_new and not form.password.data:
            flash("Укажите пароль SSH.", "danger")
            return render_template("settings.html", form=form, server=server)

        # Кнопка «Проверить подключение»: тестируем на временном объекте,
        # ничего не сохраняя в БД.
        if form.test.data:
            probe = SshServer(
                name=form.name.data,
                host=form.host.data,
                port=form.port.data,
                username=form.username.data,
                zone_file_path=form.zone_file_path.data,
                password_enc=(
                    encrypt(form.password.data)
                    if form.password.data
                    else (server.password_enc if server else "")
                ),
            )
            try:
                test_connection(probe, timeout=current_app.config["SSH_TIMEOUT"])
                flash("Подключение успешно, файл зоны доступен.", "success")
            except (SshError, RuntimeError) as exc:
                flash(str(exc), "danger")
            return render_template("settings.html", form=form, server=server)

        # Сохранение настроек.
        if is_new:
            server = SshServer()
            db.session.add(server)
        server.name = form.name.data
        server.host = form.host.data
        server.port = form.port.data
        server.username = form.username.data
        server.zone_file_path = form.zone_file_path.data
        server.is_active = form.is_active.data
        if form.password.data:
            server.password_enc = encrypt(form.password.data)
        db.session.commit()
        flash("Настройки SSH сохранены.", "success")
        return redirect(url_for("main.settings"))

    return render_template("settings.html", form=form, server=server)


# --- Заглушка выгрузки на сервер (финальная фаза) -------------------------

@main_bp.route("/push", methods=["POST"])
@operator_required
def push():
    flash(
        "Выгрузка на сервер BIND будет реализована в финальной фазе проекта.",
        "info",
    )
    return redirect(url_for("main.candidates"))
