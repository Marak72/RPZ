"""Основные маршруты: дашборд, RPZ, кандидаты по категориям, URL, IoC,
выгрузка на боевой DNS-сервер, экспорт CSV и настройки."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from ...core.extensions import db
from ...core.models import VtReport
from ...core import vt_client, vt_store
from ...core.settings_store import (
    KEY_PROTECTED,
    KEY_VT_API,
    get_protected_domains,
    get_setting,
    get_vt_key,
    set_setting,
)
from . import letters as letters_lib
from .models import (
    HASH_TYPES,
    PUSH_DRY_RUN,
    STATUS_DISMISSED,
    STATUS_FALSE_POSITIVE,
    STATUS_IGNORED,
    STATUS_IN_RPZ,
    STATUS_NEW,
    STATUS_PUSHED,
    STATUSES,
    BlockEntry,
    IocHash,
    Letter,
    LetterFile,
    PushLog,
    RpzEntry,
    RpzSnapshot,
    SshServer,
    UrlEntry,
)
from .lib import doc_parser, rpz_parser, rpz_writer
from .lib.rpz_writer import PushError
from .lib.ssh_client import SshError, read_remote_file, test_connection
from ...core.web_utils import csv_response as _csv_response
from ...core.web_utils import (
    WRITE_BATCH,
    LazyCounts,
    operator_required,
    service_guard,
)
from .forms import (
    AddFilesForm,
    AppSettingsForm,
    ManualAddForm,
    NotesForm,
    SshServerForm,
    UploadForm,
)

# Сервис живёт на своём подпути: снаружи это /soc/fstec/, в корне портала —
# главная страница со списком сервисов (blueprint hub).
fstec_bp = Blueprint("fstec", __name__, url_prefix="/fstec",
                     template_folder="templates")
# Сервис виден только тем, кому его выдал администратор.
fstec_bp.before_request(service_guard("fstec"))

PER_PAGE = 100


NAV_COUNTS_EMPTY = {"domains": 0, "ips": 0, "urls": 0, "hashes": 0,
                    "blocked": 0, "pending": 0, "documents": 0}


def _nav_counts() -> dict:
    snap = _latest_snapshot()
    blocked = {e.domain for e in snap.entries} if snap else set()
    domains = BlockEntry.query.filter_by(entry_type="domain")
    return {
        "domains": domains.count(),
        "ips": BlockEntry.query.filter_by(entry_type="ip").count(),
        "urls": UrlEntry.query.count(),
        "hashes": IocHash.query.count(),
        "blocked": len(blocked),
        "pending": sum(1 for d in domains.all()
                       if d.value not in blocked and d.status not in STATUS_DISMISSED),
        "documents": Letter.query.count(),
    }


@fstec_bp.app_context_processor
def inject_nav_counts():
    """Счётчики для боковой навигации — считаются, только если нужны."""
    if not current_user.is_authenticated:
        return {"nav_counts": LazyCounts(dict, NAV_COUNTS_EMPTY)}
    return {"nav_counts": LazyCounts(_nav_counts, NAV_COUNTS_EMPTY)}


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


def _fmt(value) -> str:
    return value.strftime("%d.%m.%Y %H:%M") if value else ""


# --- Дашборд --------------------------------------------------------------

@fstec_bp.route("/")
@login_required
def dashboard():
    snap = _latest_snapshot()
    blocked = _latest_blocked_domains()

    domains_q = BlockEntry.query.filter_by(entry_type="domain")
    stats = {
        "rpz_domains": len(blocked),
        "rpz_records": snap.entry_count if snap else 0,
        "documents": Letter.query.count(),
        "domains": domains_q.count(),
        "ips": BlockEntry.query.filter_by(entry_type="ip").count(),
        "urls": UrlEntry.query.count(),
        "hashes": IocHash.query.count(),
        "pending": domains_q.filter(BlockEntry.status == STATUS_NEW).count(),
        "pushed": domains_q.filter(BlockEntry.status == STATUS_PUSHED).count(),
        "dismissed": domains_q.filter(
            BlockEntry.status.in_(STATUS_DISMISSED)).count(),
    }

    recent_docs = (
        Letter.query.order_by(Letter.created_at.desc()).limit(5).all()
    )
    recent_pushes = (
        PushLog.query.order_by(PushLog.started_at.desc()).limit(5).all()
    )
    return render_template("fstec/dashboard.html",
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


@fstec_bp.route("/rpz")
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
    return render_template("fstec/rpz_view.html",
        snapshot=snap,
        rows=rows,
        q=q,
        action=action,
        server=_active_server(),
        blocked_total=blocked_total,
    )


@fstec_bp.route("/rpz.csv")
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


@fstec_bp.route("/rpz/refresh", methods=["POST"])
@operator_required
def rpz_refresh():
    server = _active_server()
    if not server:
        flash("Сначала настройте учётную запись SSH в разделе «Настройки».", "warning")
        return redirect(url_for("fstec.settings"))

    try:
        content = read_remote_file(server, timeout=current_app.config["SSH_TIMEOUT"])
    except (SshError, RuntimeError) as exc:
        flash(str(exc), "danger")
        return redirect(url_for("fstec.rpz_view"))
    except Exception as exc:  # noqa: BLE001 — не показывать пользователю трассировку
        current_app.logger.exception("Ошибка чтения зоны по SSH")
        flash(f"Непредвиденная ошибка при чтении зоны: {exc}", "danger")
        return redirect(url_for("fstec.rpz_view"))

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
    # Зона бывает на тысячи записей. Пишем частями: одна транзакция на всё
    # держала бы запись в SQLite секундами, и в это время ни одна страница
    # портала не смогла бы ничего сохранить.
    for index, e in enumerate(parsed, start=1):
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
        if index % WRITE_BATCH == 0:
            db.session.commit()

    # Синхронизировать статусы кандидатов с фактическим состоянием зоны.
    blocked = {e.domain for e in parsed}
    for cand in BlockEntry.query.filter_by(entry_type="domain").all():
        if cand.value in blocked and cand.status == STATUS_NEW:
            cand.status = STATUS_IN_RPZ

    db.session.commit()
    flash(f"Файл RPZ считан: {len(parsed)} записей, {len(blocked)} доменов.", "success")
    return redirect(url_for("fstec.rpz_view"))


@fstec_bp.route("/rpz/history")
@login_required
def rpz_history():
    snapshots = RpzSnapshot.query.order_by(RpzSnapshot.fetched_at.desc()).all()
    return render_template("fstec/rpz_history.html", snapshots=snapshots)


@fstec_bp.route("/rpz/history/<int:snapshot_id>")
@login_required
def rpz_snapshot_view(snapshot_id: int):
    snap = db.session.get(RpzSnapshot, snapshot_id)
    if not snap:
        abort(404)
    return render_template("fstec/rpz_snapshot.html", snapshot=snap,
                           rows=_snapshot_rows(snap))


# --- Загрузка писем ФСТЭК --------------------------------------------------
#
# Загружать можно как одно письмо с приложениями, так и целую пачку писем
# сразу: разбор сам достаёт из текста номер и дату и склеивает файлы одного
# письма в группу (см. letters.py). Оператор видит результат на предпросмотре
# и может поправить реквизиты до записи в базу.

def _letters_dir() -> str:
    path = current_app.config["LETTERS_DIR"]
    os.makedirs(path, exist_ok=True)
    return path


def _store_letter_file(data: bytes, original_name: str) -> str:
    """Сохранить файл письма в хранилище, вернуть имя файла на диске."""
    ext = os.path.splitext(original_name or "")[1].lower()[:8]
    stored = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join(_letters_dir(), stored), "wb") as fh:
        fh.write(data)
    return stored


def _drop_stored(stored_name: str) -> None:
    if not stored_name:
        return
    try:
        os.remove(os.path.join(current_app.config["LETTERS_DIR"], stored_name))
    except OSError:
        current_app.logger.warning("Не удалось удалить файл письма %s", stored_name)


def _known_hashes() -> dict:
    """sha256 уже загруженных файлов → как называется письмо-владелец."""
    rows = (
        db.session.query(LetterFile.sha256, Letter.number, Letter.id)
        .join(Letter, LetterFile.letter_id == Letter.id)
        .filter(LetterFile.sha256 != "")
        .all()
    )
    return {sha: (number or f"#{lid}") for sha, number, lid in rows}


def _split_extracted(groups) -> dict:
    """Разложить найденное по категориям с отметками о наличии в базе.

    Один и тот же индикатор встречается в нескольких файлах пачки — в списке
    он показывается один раз, но помнит все места, где встретился: аналитику
    важно видеть, что домен пришёл сразу из двух писем.
    """
    existing = {b.value for b in BlockEntry.query.all()}
    existing_urls = {u.value for u in UrlEntry.query.all()}
    existing_hashes = {h.value for h in IocHash.query.all()}
    blocked = _latest_blocked_domains()

    buckets = {"domains": [], "ips": [], "urls": [], "hashes": []}
    seen: dict[tuple, dict] = {}

    for group_index, letter in enumerate(groups):
        for parsed_file in letter.files:
            for entry in parsed_file.entries:
                key = (entry.entry_type, entry.value)
                known = seen.get(key)
                if known is not None:
                    # Уже видели — только дописываем источник.
                    if letter.number and letter.number not in known["letters"]:
                        known["letters"].append(letter.number)
                    continue

                item = {
                    "value": entry.value,
                    "type": entry.entry_type,
                    "file": parsed_file.index,
                    "group": group_index,
                    "letters": [letter.number] if letter.number else [],
                    "file_name": parsed_file.filename,
                }
                if entry.entry_type == "domain":
                    item["already_in_db"] = entry.value in existing
                    item["in_rpz"] = entry.value in blocked
                    buckets["domains"].append(item)
                elif entry.entry_type == "ip":
                    item["already_in_db"] = entry.value in existing
                    item["in_rpz"] = False
                    buckets["ips"].append(item)
                elif entry.entry_type == "url":
                    item["host"] = entry.host
                    item["already_in_db"] = entry.value in existing_urls
                    buckets["urls"].append(item)
                elif entry.entry_type in HASH_TYPES:
                    item["already_in_db"] = entry.value in existing_hashes
                    buckets["hashes"].append(item)
                else:
                    continue
                seen[key] = item

    return buckets


def _groups_payload(groups) -> list:
    """Структура групп для скрытого поля формы предпросмотра."""
    payload = []
    for letter in groups:
        payload.append({
            "number": letter.number,
            "date": letter.letter_date.isoformat() if letter.letter_date else "",
            "files": [
                {
                    "index": f.index,
                    "filename": f.filename,
                    "stored_name": f.stored_name,
                    "content_type": f.content_type,
                    "file_size": f.size,
                    "sha256": f.sha256,
                    "is_primary": f.is_primary,
                    "entries_found": len(f.entries),
                    "error": f.error,
                    "duplicate_of": f.duplicate_of,
                }
                for f in letter.files
            ],
        })
    return payload


@fstec_bp.route("/upload", methods=["GET", "POST"])
@operator_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        files = [f for f in (form.documents.data or []) if f and f.filename]
        if not files:
            flash("Выберите хотя бы один файл письма.", "danger")
            return render_template("fstec/upload.html", form=form)

        uploaded = [(f.filename, f.read(), f.mimetype or "") for f in files]
        groups = letters_lib.parse_batch(
            uploaded,
            known_hashes=_known_hashes(),
            forced_number=(form.letter_number.data or "").strip(),
            forced_date=form.letter_date.data,
        )

        # Файлы кладём на диск сразу: до сохранения пользователь ещё будет
        # ходить по предпросмотру, и держать их в сессии незачем.
        try:
            for letter in groups:
                for parsed_file in letter.files:
                    parsed_file.stored_name = _store_letter_file(
                        parsed_file.data, parsed_file.filename
                    )
        except OSError as exc:
            current_app.logger.exception("Не удалось сохранить файл письма")
            flash(f"Не удалось сохранить файл письма: {exc}", "danger")
            return render_template("fstec/upload.html", form=form)

        buckets = _split_extracted(groups)
        total = sum(len(v) for v in buckets.values())

        problems = [f for letter in groups for f in letter.files if f.error]
        for parsed_file in problems:
            flash(f"«{parsed_file.filename}»: {parsed_file.error}", "warning")

        duplicates = [f for letter in groups for f in letter.files
                      if f.duplicate_of]
        for parsed_file in duplicates:
            flash(
                f"Файл «{parsed_file.filename}» уже загружен в письме "
                f"{parsed_file.duplicate_of} — повторно сохранён не будет.",
                "warning",
            )

        if total == 0:
            flash(
                "Ни в одном файле не найдено индикаторов, но файлы сохранены. "
                "Индикаторы можно добавить вручную.",
                "warning",
            )

        payload = _groups_payload(groups)
        return render_template(
            "fstec/preview.html",
            groups=buckets,
            letter_groups=payload,
            groups_json=json.dumps(payload, ensure_ascii=False),
            notes=form.notes.data or "",
            total=total,
        )
    return render_template("fstec/upload.html", form=form)


@fstec_bp.route("/preview/csv", methods=["POST"])
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
        return redirect(url_for("fstec.upload"))
    return _csv_response("fstec-parsed", ["Категория", "Значение", "Тип"], rows)


def _split_choice(raw: str) -> tuple:
    """Разобрать значение чекбокса вида ``<индекс файла>|<значение>``."""
    index, _, value = str(raw).partition("|")
    if not _:
        return 0, index.strip()
    return (int(index) if index.strip().isdigit() else 0), value.strip()


def _parse_date(raw: str):
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date() if raw else None
    except ValueError:
        return None


def _letter_for_number(number: str, letter_date, notes: str) -> Letter:
    """Найти письмо с таким номером или завести новое.

    Приложение к письму часто приходит отдельно и позже основного письма.
    Поэтому файлы с уже известным номером присоединяются к существующему
    письму, а не создают его двойник.
    """
    key = letters_lib.normalize_number(number)
    letter = None
    if key:
        letter = Letter.query.filter_by(number_key=key).first()
    if letter is None:
        letter = Letter(
            number=number,
            number_key=key,
            letter_date=letter_date,
            notes=notes,
            created_by=current_user.id,
        )
        db.session.add(letter)
    else:
        # Дату и примечание дополняем, но не затираем уже введённое вручную.
        if letter_date and not letter.letter_date:
            letter.letter_date = letter_date
        if notes and not letter.notes:
            letter.notes = notes
    return letter


@fstec_bp.route("/preview", methods=["POST"])
@operator_required
def preview_save():
    selected = request.form.getlist("selected")
    selected_urls = request.form.getlist("selected_url")
    selected_hashes = request.form.getlist("selected_hash")
    notes = request.form.get("notes", "")

    try:
        payload = json.loads(request.form.get("groups_json") or "[]")
    except (ValueError, TypeError):
        payload = []
    if not payload:
        flash("Данные о загруженных файлах потерялись — загрузите письма заново.",
              "danger")
        return redirect(url_for("fstec.upload"))

    if not (selected or selected_urls or selected_hashes):
        flash("Не выбрано ни одной записи, но сами файлы сохранены.", "warning")

    blocked = _latest_blocked_domains()

    # Реквизиты письма оператор мог поправить на предпросмотре.
    letters: list[Letter] = []
    file_to_letter: dict[int, Letter] = {}
    file_rows: dict[int, LetterFile] = {}

    for group_index, group in enumerate(payload):
        number = (request.form.get(f"group_number_{group_index}")
                  or group.get("number") or "").strip()
        letter_date = _parse_date(
            request.form.get(f"group_date_{group_index}") or group.get("date") or ""
        )
        letter = _letter_for_number(number, letter_date, notes)
        # Оператор мог задать двум группам один номер — это указание «свести
        # их в одно письмо», а не завести два одинаковых.
        if letter not in letters:
            letters.append(letter)
        db.session.flush()

        for item in group.get("files", []):
            index = int(item.get("index") or 0)
            file_to_letter[index] = letter
            if item.get("duplicate_of"):
                # Тот же файл уже лежит в архиве — второй копии не заводим.
                _drop_stored(item.get("stored_name", ""))
                continue
            row = LetterFile(
                letter_id=letter.id,
                filename=item.get("filename") or "файл",
                stored_name=item.get("stored_name", ""),
                content_type=item.get("content_type", ""),
                file_size=int(item.get("file_size") or 0),
                sha256=item.get("sha256", ""),
                is_primary=bool(item.get("is_primary")),
                parse_error=(item.get("error") or "")[:500],
                uploaded_by=current_user.id,
            )
            db.session.add(row)
            file_rows[index] = row

    db.session.flush()

    counts = {}
    added = urls_added = hashes_added = 0

    def _link(entry, index: int) -> None:
        """Привязать индикатор к письму, из которого он пришёл."""
        letter = file_to_letter.get(index) or (letters[0] if letters else None)
        if letter is None:
            return
        if letter not in entry.letters:
            entry.letters.append(letter)
        row = file_rows.get(index)
        if row is not None:
            counts[row.id] = counts.get(row.id, 0) + 1

    for raw in selected:
        index, value = _split_choice(raw)
        value = value.lower()
        if not value:
            continue
        is_ip = doc_parser._valid_ipv4(value)
        # Не сохраняем мусор: домен обязан пройти строгую валидацию.
        if not is_ip and not doc_parser.is_valid_domain(value):
            continue
        entry = BlockEntry.query.filter_by(value=value).first()
        if entry is None:
            entry = BlockEntry(
                value=value,
                entry_type="ip" if is_ip else "domain",
                status=STATUS_IN_RPZ if value in blocked else STATUS_NEW,
                added_by=current_user.id,
            )
            db.session.add(entry)
            added += 1
        _link(entry, index)

    for raw in selected_urls:
        index, value = _split_choice(raw)
        if not value:
            continue
        entry = UrlEntry.query.filter_by(value=value).first()
        if entry is None:
            parsed = doc_parser._parse_url(value)
            entry = UrlEntry(
                value=value,
                host=parsed[0] if parsed else "",
                added_by=current_user.id,
            )
            db.session.add(entry)
            urls_added += 1
        _link(entry, index)

    for raw in selected_hashes:
        index, value = _split_choice(raw)
        value = value.lower()
        if not value:
            continue
        entry = IocHash.query.filter_by(value=value).first()
        if entry is None:
            entry = IocHash(
                value=value,
                hash_type=_hash_type_of(value),
                added_by=current_user.id,
            )
            db.session.add(entry)
            hashes_added += 1
        _link(entry, index)

    for index, row in file_rows.items():
        row.entries_found = counts.get(row.id, 0)

    try:
        db.session.commit()
    except Exception as exc:  # noqa: BLE001 — например, гонка по уникальному индексу
        db.session.rollback()
        current_app.logger.exception("Ошибка сохранения индикаторов")
        flash(f"Не удалось сохранить записи: {exc}", "danger")
        return redirect(url_for("fstec.upload"))

    word = ("Письмо сохранено" if len(letters) == 1
            else f"Сохранено писем: {len(letters)}")
    flash(
        f"{word}. Новых адресов — {added}, URL — {urls_added}, "
        f"хешей — {hashes_added}.",
        "success",
    )
    if len(letters) == 1:
        return redirect(url_for("fstec.letter_view", letter_id=letters[0].id))
    return redirect(url_for("fstec.documents"))


def _hash_type_of(value: str) -> str:
    return {64: "sha256", 40: "sha1", 32: "md5"}.get(len(value), "sha256")


# --- Письма ФСТЭК ----------------------------------------------------------

@fstec_bp.route("/letters")
@login_required
def documents():
    q = request.args.get("q", "").strip()
    query = Letter.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                Letter.number.ilike(like),
                Letter.subject.ilike(like),
                Letter.notes.ilike(like),
                Letter.files.any(LetterFile.filename.ilike(like)),
            )
        )
    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(
        Letter.letter_date.desc().nullslast(), Letter.created_at.desc()
    ).paginate(page=page, per_page=50, error_out=False)

    stats = {}
    for letter in pagination.items:
        stats[letter.id] = {
            "domains": letter.block_entries.filter_by(entry_type="domain").count(),
            "ips": letter.block_entries.filter_by(entry_type="ip").count(),
            "urls": letter.url_entries.count(),
            "hashes": letter.ioc_hashes.count(),
            "files": len(letter.files),
        }
    return render_template(
        "fstec/documents.html", pagination=pagination, items=pagination.items,
        q=q, stats=stats,
    )


@fstec_bp.route("/letters/<int:letter_id>")
@login_required
def letter_view(letter_id: int):
    letter = db.session.get(Letter, letter_id)
    if not letter:
        abort(404)
    return render_template(
        "fstec/document.html",
        letter=letter,
        domains=letter.block_entries.filter_by(entry_type="domain")
                      .order_by(BlockEntry.value).all(),
        ips=letter.block_entries.filter_by(entry_type="ip")
                  .order_by(BlockEntry.value).all(),
        urls=letter.url_entries.order_by(UrlEntry.value).all(),
        hashes=letter.ioc_hashes.order_by(IocHash.value).all(),
        add_form=AddFilesForm(),
    )


@fstec_bp.route("/letters/<int:letter_id>/edit", methods=["POST"])
@operator_required
def letter_edit(letter_id: int):
    """Поправить реквизиты письма: номер, дату, тему, примечание."""
    letter = db.session.get(Letter, letter_id)
    if not letter:
        abort(404)
    number = (request.form.get("number") or "").strip()
    key = letters_lib.normalize_number(number)
    clash = Letter.query.filter(Letter.number_key == key,
                                Letter.id != letter.id).first() if key else None
    if clash:
        flash(f"Письмо с номером {number} уже есть в архиве.", "danger")
        return redirect(url_for("fstec.letter_view", letter_id=letter.id))

    letter.number = number
    letter.number_key = key
    letter.letter_date = _parse_date(request.form.get("letter_date", ""))
    letter.subject = (request.form.get("subject") or "").strip()[:500]
    letter.notes = (request.form.get("notes") or "").strip()[:1000]
    db.session.commit()
    flash("Реквизиты письма сохранены.", "success")
    return redirect(url_for("fstec.letter_view", letter_id=letter.id))


@fstec_bp.route("/letters/<int:letter_id>/files", methods=["POST"])
@operator_required
def letter_add_files(letter_id: int):
    """Дослать файлы к уже заведённому письму.

    Приложения к письму нередко приходят позже самого письма — заводить из-за
    этого второе письмо с тем же номером неправильно.
    """
    letter = db.session.get(Letter, letter_id)
    if not letter:
        abort(404)
    form = AddFilesForm()
    if not form.validate_on_submit():
        flash("Не удалось принять файлы: проверьте формат.", "danger")
        return redirect(url_for("fstec.letter_view", letter_id=letter.id))

    files = [f for f in (form.documents.data or []) if f and f.filename]
    if not files:
        flash("Выберите хотя бы один файл.", "warning")
        return redirect(url_for("fstec.letter_view", letter_id=letter.id))

    known = _known_hashes()
    added = skipped = 0
    for uploaded in files:
        data = uploaded.read()
        digest = hashlib.sha256(data).hexdigest()
        if digest in known:
            skipped += 1
            continue
        try:
            stored = _store_letter_file(data, uploaded.filename)
        except OSError as exc:
            current_app.logger.exception("Не удалось сохранить файл письма")
            flash(f"Не удалось сохранить файл: {exc}", "danger")
            break
        db.session.add(LetterFile(
            letter_id=letter.id,
            filename=secure_filename(uploaded.filename) or uploaded.filename,
            stored_name=stored,
            content_type=uploaded.mimetype or "",
            file_size=len(data),
            sha256=digest,
            uploaded_by=current_user.id,
        ))
        added += 1

    db.session.commit()
    if added:
        flash(f"Добавлено файлов: {added}. Индикаторы из них можно распознать "
              "через «Загрузить письма».", "success")
    if skipped:
        flash(f"Пропущено уже загруженных файлов: {skipped}.", "warning")
    return redirect(url_for("fstec.letter_view", letter_id=letter.id))


def _letter_rows(letter) -> list:
    """Все индикаторы письма одним списком — для выгрузки и общего экспорта."""
    rows = []
    number = letter.number or ""
    when = _fmt_date(letter.letter_date)

    for entry in letter.block_entries.order_by(BlockEntry.entry_type,
                                               BlockEntry.value).all():
        vt = entry.vt
        rows.append([
            "домен" if entry.entry_type == "domain" else "IP-адрес",
            entry.value,
            entry.status_title,
            vt.score if vt else "",
            vt.verdict if vt else "",
            number,
            when,
            entry.notes or "",
        ])
    for url in letter.url_entries.order_by(UrlEntry.value).all():
        rows.append(["URL", url.value, "", "", "", number, when, url.notes or ""])
    for ioc in letter.ioc_hashes.order_by(IocHash.value).all():
        rows.append([ioc.hash_type, ioc.value, "", "", "", number, when,
                     ioc.notes or ""])
    return rows


LETTER_CSV_HEADER = ["Тип", "Значение", "Статус", "VT", "Вердикт VT",
                     "Номер письма", "Дата письма", "Примечание"]


def _fmt_date(value) -> str:
    return value.strftime("%d.%m.%Y") if value else ""


@fstec_bp.route("/letters/<int:letter_id>.csv")
@login_required
def document_csv(letter_id: int):
    """Все индикаторы одного письма: домены, IP, URL и хеши в одном файле."""
    letter = db.session.get(Letter, letter_id)
    if not letter:
        abort(404)
    name = (letter.number or f"letter-{letter.id}").replace("/", "-")
    return _csv_response(f"fstec-{name}", LETTER_CSV_HEADER, _letter_rows(letter))


@fstec_bp.route("/letters.csv")
@login_required
def documents_csv():
    """Сводная выгрузка: индикаторы всех писем с привязкой к письму."""
    rows = []
    for letter in Letter.query.order_by(Letter.created_at.desc()).all():
        rows.extend(_letter_rows(letter))
    return _csv_response("fstec-letters", LETTER_CSV_HEADER, rows)


@fstec_bp.route("/letters/<int:letter_id>/files/<int:file_id>")
@login_required
def letter_file(letter_id: int, file_id: int):
    """Отдать файл письма: PDF — для просмотра, остальное — на скачивание."""
    row = db.session.get(LetterFile, file_id)
    if not row or row.letter_id != letter_id or not row.stored_name:
        abort(404)
    directory = current_app.config["LETTERS_DIR"]
    if not os.path.exists(os.path.join(directory, row.stored_name)):
        flash("Файл письма не найден в хранилище.", "warning")
        return redirect(url_for("fstec.letter_view", letter_id=letter_id))

    return send_from_directory(
        directory, row.stored_name,
        as_attachment=not row.is_pdf,
        download_name=row.filename or row.stored_name,
        mimetype="application/pdf" if row.is_pdf else None,
    )


@fstec_bp.route("/letters/<int:letter_id>/files/<int:file_id>/delete",
                methods=["POST"])
@operator_required
def letter_file_delete(letter_id: int, file_id: int):
    row = db.session.get(LetterFile, file_id)
    if not row or row.letter_id != letter_id:
        abort(404)
    _drop_stored(row.stored_name)
    db.session.delete(row)
    db.session.commit()
    flash("Файл удалён из письма. Индикаторы остались в базе.", "success")
    return redirect(url_for("fstec.letter_view", letter_id=letter_id))


@fstec_bp.route("/letters/<int:letter_id>/delete", methods=["POST"])
@operator_required
def document_delete(letter_id: int):
    """Удалить письмо. Индикаторы сохраняются, но теряют привязку к нему."""
    letter = db.session.get(Letter, letter_id)
    if not letter:
        abort(404)
    for row in letter.files:
        _drop_stored(row.stored_name)
    # Связи «индикатор ↔ письмо» уходят вместе с письмом, сами индикаторы —
    # нет: они могли прийти и из других писем, и быть уже выгружены в зону.
    letter.block_entries = []
    letter.url_entries = []
    letter.ioc_hashes = []
    db.session.delete(letter)
    db.session.commit()
    flash("Письмо удалено. Индикаторы остались в базе.", "success")
    return redirect(url_for("fstec.documents"))


# --- Карточка индикатора ---------------------------------------------------

@fstec_bp.route("/object/<int:entry_id>", methods=["GET", "POST"])
@login_required
def object_view(entry_id: int):
    entry = db.session.get(BlockEntry, entry_id)
    if not entry:
        abort(404)

    form = NotesForm(obj=entry)
    if form.validate_on_submit():
        if not current_user.is_operator:
            abort(403)
        entry.notes = form.notes.data or ""
        db.session.commit()
        flash("Заметка сохранена.", "success")
        return redirect(url_for("fstec.object_view", entry_id=entry.id))

    blocked = _latest_blocked_domains()
    related_urls = (
        UrlEntry.query.filter_by(host=entry.value).all()
        if entry.entry_type == "domain" else []
    )
    pushes = (
        PushLog.query.filter(PushLog.domains.like(f"%{entry.value}%"))
        .order_by(PushLog.started_at.desc()).limit(10).all()
    )
    return render_template("fstec/object.html",
        entry=entry,
        form=form,
        in_rpz=entry.value in blocked,
        vt=entry.vt,
        related_urls=related_urls,
        pushes=pushes,
        protected=entry.value in get_protected_domains(),
        vt_configured=bool(get_vt_key()),
    )


@fstec_bp.route("/object/<int:entry_id>/delete", methods=["POST"])
@operator_required
def object_delete(entry_id: int):
    entry = db.session.get(BlockEntry, entry_id)
    if not entry:
        abort(404)
    value, etype = entry.value, entry.entry_type
    db.session.delete(entry)
    db.session.commit()
    flash(f"Запись {value} удалена из базы (в зоне RPZ она не изменялась).", "success")
    return redirect(url_for("fstec.candidates", type=etype))


# --- Ручное добавление индикаторов ----------------------------------------

@fstec_bp.route("/manual", methods=["GET", "POST"])
@operator_required
def manual_add():
    form = ManualAddForm()
    if form.validate_on_submit():
        blocked = _latest_blocked_domains()
        existing = {b.value for b in BlockEntry.query.all()}
        added, skipped, rejected = 0, 0, []
        for raw in (form.values.data or "").replace(",", "\n").splitlines():
            value = doc_parser.refang(raw).strip().lower().rstrip(".")
            if not value:
                continue
            is_ip = doc_parser._valid_ipv4(value)
            if not is_ip and not doc_parser.is_valid_domain(value):
                rejected.append(raw.strip())
                continue
            if value in existing:
                skipped += 1
                continue
            db.session.add(
                BlockEntry(
                    value=value,
                    entry_type="ip" if is_ip else "domain",
                    status=STATUS_IN_RPZ if value in blocked else STATUS_NEW,
                    added_by=current_user.id,
                    source="manual",
                    notes=form.notes.data or "",
                )
            )
            existing.add(value)
            added += 1
        db.session.commit()

        if rejected:
            flash("Не распознано как домен или IP: " + ", ".join(rejected[:10]), "warning")
        if added:
            flash(f"Добавлено вручную: {added}. Уже были в базе: {skipped}.", "success")
            return redirect(url_for("fstec.candidates"))
        if not rejected:
            flash(f"Новых записей нет — все {skipped} уже в базе.", "info")
    return render_template("fstec/manual.html", form=form)


# --- VirusTotal ------------------------------------------------------------

def _save_vt(result, error: str = "", value: str = "", kind: str = "domain") -> VtReport:
    """Сохранить (или обновить) отчёт VirusTotal.

    Сама запись живёт в ``vt_store``: отчёт общий с сервисом SkyDNS, и две
    копии логики сохранения разъехались бы при первой же правке.
    """
    return vt_store.store(result, error=error, value=value, kind=kind,
                          user_id=current_user.id)


@fstec_bp.route("/vt/check", methods=["POST"])
@operator_required
def vt_check():
    """Проверить одно значение в VirusTotal."""
    value = (request.form.get("value") or "").strip().lower()
    back = request.form.get("next") or url_for("fstec.candidates")
    if not value:
        flash("Не указано значение для проверки.", "warning")
        return redirect(back)

    key = get_vt_key()
    try:
        result = vt_client.check(value, key, timeout=current_app.config["VT_TIMEOUT"])
        _save_vt(result)
        db.session.commit()
        flash(
            f"VirusTotal: {value} — вредоносных вердиктов {result.malicious} "
            f"из {result.total_engines}.",
            "danger" if result.malicious else "success",
        )
    except vt_client.VtError as exc:
        _save_vt(None, error=str(exc), value=value)
        db.session.commit()
        flash(str(exc), "danger")
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        current_app.logger.exception("Ошибка запроса к VirusTotal")
        flash(f"Непредвиденная ошибка при обращении к VirusTotal: {exc}", "danger")
    return redirect(back)


@fstec_bp.route("/vt/check-batch", methods=["POST"])
@operator_required
def vt_check_batch():
    """Проверить пачку непроверенных индикаторов с учётом лимитов VT."""
    limit = current_app.config["VT_BATCH_LIMIT"]
    checked_values = {r.value for r in VtReport.query.filter_by(error="").all()}
    pending = [
        e for e in BlockEntry.query.order_by(BlockEntry.created_at.desc()).all()
        if e.value not in checked_values
    ][:limit]

    if not pending:
        flash("Все индикаторы уже проверены в VirusTotal.", "info")
        return redirect(url_for("fstec.candidates"))

    key = get_vt_key()
    done, failed = 0, 0
    for entry in pending:
        try:
            result = vt_client.check(
                entry.value, key, timeout=current_app.config["VT_TIMEOUT"]
            )
            _save_vt(result)
            done += 1
        except vt_client.VtRateLimit as exc:
            db.session.commit()
            flash(
                f"Проверено {done}, затем сработал лимит VirusTotal. {exc}", "warning"
            )
            return redirect(url_for("fstec.candidates"))
        except vt_client.VtError as exc:
            _save_vt(None, error=str(exc), value=entry.value)
            failed += 1
            if "ключ" in str(exc).lower():
                db.session.commit()
                flash(str(exc), "danger")
                return redirect(url_for("fstec.settings"))
    db.session.commit()
    flash(f"VirusTotal: проверено {done}, с ошибкой {failed}.", "success" if done else "warning")
    return redirect(url_for("fstec.candidates"))


# --- Кандидаты (домены и IP) ----------------------------------------------

#: Значения фильтра по вердикту VirusTotal.
VT_FILTERS = (
    ("malicious", "вредоносный"),
    ("suspicious", "подозрительный"),
    ("clean", "чистый"),
    ("unchecked", "не проверялся"),
)


def _candidates_filters() -> dict:
    """Разобрать параметры фильтра из строки запроса."""
    return {
        "q": request.args.get("q", "").strip().lower(),
        "status": request.args.get("status", "").strip(),
        "etype": request.args.get("type", "").strip(),
        "vt": request.args.get("vt", "").strip(),
        "letter": request.args.get("letter", type=int),
        "source": request.args.get("source", "").strip(),
    }


def _candidates_query(flt: dict):
    query = BlockEntry.query
    if flt["q"]:
        query = query.filter(BlockEntry.value.like(f"%{flt['q']}%"))
    if flt["status"]:
        query = query.filter_by(status=flt["status"])
    if flt["etype"]:
        query = query.filter_by(entry_type=flt["etype"])
    if flt["source"]:
        query = query.filter_by(source=flt["source"])
    if flt["letter"]:
        query = query.filter(BlockEntry.letters.any(Letter.id == flt["letter"]))

    if flt["vt"]:
        # Вердикт VirusTotal считается в Python (VtReport.verdict — свойство),
        # поэтому фильтруем по заранее собранному списку значений.
        checked = {r.value: r.verdict for r in VtReport.query.all()}
        if flt["vt"] == "unchecked":
            wanted = None
            query = query.filter(~BlockEntry.value.in_(list(checked)))
        else:
            wanted = [v for v, verdict in checked.items() if verdict == flt["vt"]]
            query = query.filter(BlockEntry.value.in_(wanted or [""]))

    return query.order_by(BlockEntry.created_at.desc())


@fstec_bp.route("/candidates")
@login_required
def candidates():
    flt = _candidates_filters()
    page = request.args.get("page", 1, type=int)
    pagination = _candidates_query(flt).paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )
    counts = {
        "all": BlockEntry.query.count(),
        "domain": BlockEntry.query.filter_by(entry_type="domain").count(),
        "ip": BlockEntry.query.filter_by(entry_type="ip").count(),
    }
    return render_template("fstec/candidates.html",
        pagination=pagination,
        items=pagination.items,
        q=flt["q"],
        status=flt["status"],
        etype=flt["etype"],
        vt=flt["vt"],
        source=flt["source"],
        letter_id=flt["letter"],
        letter=db.session.get(Letter, flt["letter"]) if flt["letter"] else None,
        counts=counts,
        statuses=STATUSES,
        vt_filters=VT_FILTERS,
    )


@fstec_bp.route("/candidates.csv")
@login_required
def candidates_csv():
    query = _candidates_query(_candidates_filters())
    return _csv_response(
        "fstec-candidates",
        ["Значение", "Тип", "Статус", "Письма", "Источник", "Добавлен",
         "Выгружен", "Решение"],
        [
            [
                it.value, it.entry_type, it.status_title, it.letter_numbers,
                it.source, _fmt(it.created_at), _fmt(it.pushed_at),
                it.decision_note or "",
            ]
            for it in query.all()
        ],
    )


# --- Массовые действия над индикаторами ------------------------------------

#: Что можно сделать с отмеченными записями списка.
BULK_ACTIONS = {
    "fp": (STATUS_FALSE_POSITIVE, "помечены как ложное срабатывание"),
    "ignore": (STATUS_IGNORED, "помечены «не блокируем»"),
    "restore": (STATUS_NEW, "возвращены в работу"),
}


@fstec_bp.route("/candidates/bulk", methods=["POST"])
@operator_required
def candidates_bulk():
    """Массовое действие над отмеченными индикаторами.

    Разбирать письмо построчно — это десятки одинаковых решений подряд,
    поэтому решение принимается сразу для группы записей.
    """
    action = request.form.get("action", "")
    ids = [int(x) for x in request.form.getlist("ids") if str(x).isdigit()]
    back = request.form.get("back") or url_for("fstec.candidates")

    if not ids:
        flash("Не отмечено ни одной записи.", "warning")
        return redirect(back)

    entries = BlockEntry.query.filter(BlockEntry.id.in_(ids)).all()

    if action == "delete":
        for entry in entries:
            entry.letters = []
            db.session.delete(entry)
        db.session.commit()
        flash(f"Удалено записей: {len(entries)}.", "success")
        return redirect(back)

    if action not in BULK_ACTIONS:
        flash("Неизвестное действие.", "danger")
        return redirect(back)

    status, what = BULK_ACTIONS[action]
    note = (request.form.get("note") or "").strip()[:500]
    if status in STATUS_DISMISSED and not note:
        flash("Укажите причину — без неё через месяц не понять, почему "
              "индикатор не заблокирован.", "danger")
        return redirect(back)

    blocked = _latest_blocked_domains()
    changed = 0
    for entry in entries:
        if status == STATUS_NEW:
            # Возврат в работу: статус восстанавливаем по факту наличия в зоне.
            entry.status = STATUS_IN_RPZ if entry.value in blocked else STATUS_NEW
            entry.decision_note = ""
            entry.decided_at = None
            entry.decided_by = None
        else:
            entry.status = status
            entry.decision_note = note
            entry.decided_at = datetime.utcnow()
            entry.decided_by = current_user.id
        changed += 1

    db.session.commit()
    flash(f"Записей {what}: {changed}.", "success")
    return redirect(back)


# --- Глобальный поиск по всем индикаторам ----------------------------------

@fstec_bp.route("/search")
@login_required
def search():
    """Один ответ на вопрос «есть ли у нас этот адрес и откуда он».

    Ищет сразу по доменам, IP, ссылкам и хешам: аналитику приходит запрос
    «проверьте вот это», и обходить четыре раздела по очереди неудобно.
    """
    q = request.args.get("q", "").strip().lower()
    result = {"entries": [], "urls": [], "hashes": [], "zone": []}

    if q:
        like = f"%{q}%"
        result["entries"] = (BlockEntry.query.filter(BlockEntry.value.like(like))
                             .order_by(BlockEntry.value).limit(100).all())
        result["urls"] = (UrlEntry.query
                          .filter(db.or_(UrlEntry.value.like(like),
                                         UrlEntry.host.like(like)))
                          .order_by(UrlEntry.value).limit(100).all())
        result["hashes"] = (IocHash.query.filter(IocHash.value.like(like))
                            .order_by(IocHash.value).limit(100).all())
        # Зона могла быть наполнена и не через портал — ищем и в ней.
        snap = _latest_snapshot()
        if snap:
            result["zone"] = sorted(
                {e.domain for e in snap.entries if q in e.domain}
            )[:100]

    total = sum(len(v) for v in result.values())
    return render_template("fstec/search.html", q=q, result=result, total=total)


# --- URL с путями ----------------------------------------------------------

@fstec_bp.route("/urls")
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
    return render_template("fstec/urls.html", pagination=pagination, items=pagination.items, q=q
    )


@fstec_bp.route("/urls.csv")
@login_required
def urls_csv():
    items = UrlEntry.query.order_by(UrlEntry.created_at.desc()).all()
    return _csv_response(
        "fstec-urls",
        ["URL", "Хост", "Письма", "Добавлен"],
        [
            [it.value, it.host, it.letter_numbers,
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


@fstec_bp.route("/iocs")
@login_required
def iocs():
    query, q, htype = _iocs_query()
    page = request.args.get("page", 1, type=int)
    pagination = query.paginate(page=page, per_page=PER_PAGE, error_out=False)
    counts = {t: IocHash.query.filter_by(hash_type=t).count() for t in HASH_TYPES}
    return render_template("fstec/iocs.html", pagination=pagination, items=pagination.items,
        q=q, htype=htype, counts=counts,
    )


@fstec_bp.route("/iocs.csv")
@login_required
def iocs_csv():
    query, *_ = _iocs_query()
    return _csv_response(
        "fstec-hashes",
        ["Хеш", "Тип", "Письма", "Добавлен"],
        [
            [it.value, it.hash_type, it.letter_numbers,
             _fmt(it.created_at)]
            for it in query.all()
        ],
    )


# --- Выгрузка на боевой DNS-сервер ----------------------------------------

@fstec_bp.route("/push")
@login_required
def push_view():
    """Экран выбора доменов для выгрузки: видно, что уже в RPZ, а что нет."""
    blocked = _latest_blocked_domains()
    domains = (
        BlockEntry.query.filter_by(entry_type="domain")
        .order_by(BlockEntry.created_at.desc())
        .all()
    )
    vt_map = {r.value: r for r in VtReport.query.all()}
    protected = get_protected_domains()
    rows = []
    for d in domains:
        rows.append({
            "id": d.id,
            "value": d.value,
            "status": d.status,
            "in_rpz": d.value in blocked,
            "pushed_at": d.pushed_at,
            "letter": d.first_letter,
            "letter_numbers": d.letter_numbers,
            "source": d.source,
            "vt": vt_map.get(d.value),
            "protected": d.value in protected,
        })
    # Домены, которые есть в зоне, но которых нет в базе кандидатов —
    # их тоже можно снять с блокировки.
    known = {d.value for d in domains}
    for extra in sorted(blocked - known):
        rows.append({
            "id": None, "value": extra, "status": "in_rpz", "in_rpz": True,
            "pushed_at": None, "letter": None, "letter_numbers": "",
            "source": "zone",
            "vt": vt_map.get(extra), "protected": extra in protected,
        })

    pending = [r for r in rows if not r["in_rpz"]]
    return render_template("fstec/push.html",
        rows=rows,
        pending_count=len(pending),
        in_zone_count=sum(1 for r in rows if r["in_rpz"]),
        server=_active_server(),
        snapshot=_latest_snapshot(),
        ip_count=BlockEntry.query.filter_by(entry_type="ip").count(),
    )


@fstec_bp.route("/push", methods=["POST"])
@operator_required
def push_run():
    """Выгрузить выбранные домены в RPZ-зону (или показать предпросмотр)."""
    selected = [v.strip().lower() for v in request.form.getlist("domains") if v.strip()]
    dry_run = bool(request.form.get("dry_run"))

    server = _active_server()
    if not server:
        flash("Сначала настройте учётную запись SSH в разделе «Настройки».", "warning")
        return redirect(url_for("fstec.settings"))
    if not selected:
        flash("Не выбрано ни одного домена для выгрузки.", "warning")
        return redirect(url_for("fstec.push_view"))

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
            protected=get_protected_domains(),
        )
    except (PushError, SshError, RuntimeError) as exc:
        log.status = "failed"
        log.message = str(exc)
        log.domains = ", ".join(selected)
        log.finished_at = datetime.utcnow()
        db.session.add(log)
        db.session.commit()
        flash(f"Выгрузка не выполнена: {exc}", "danger")
        return redirect(url_for("fstec.push_log_view", log_id=log.id))
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Непредвиденная ошибка выгрузки")
        log.status = "failed"
        log.message = f"Непредвиденная ошибка: {exc}"
        log.domains = ", ".join(selected)
        log.finished_at = datetime.utcnow()
        db.session.add(log)
        db.session.commit()
        flash(f"Непредвиденная ошибка при выгрузке: {exc}", "danger")
        return redirect(url_for("fstec.push_log_view", log_id=log.id))

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

    return redirect(url_for("fstec.push_log_view", log_id=log.id))


@fstec_bp.route("/push/remove", methods=["POST"])
@operator_required
def push_remove():
    """Снять блокировку: удалить выбранные домены из RPZ-зоны."""
    selected = [v.strip().lower() for v in request.form.getlist("domains") if v.strip()]
    dry_run = bool(request.form.get("dry_run"))

    server = _active_server()
    if not server:
        flash("Сначала настройте учётную запись SSH в разделе «Настройки».", "warning")
        return redirect(url_for("fstec.settings"))
    if not selected:
        flash("Не выбрано ни одного домена для удаления из зоны.", "warning")
        return redirect(url_for("fstec.push_view"))

    log = PushLog(server_id=server.id, user_id=current_user.id,
                  status="failed", entries_count=0)
    try:
        result = rpz_writer.remove_domains(
            server,
            selected,
            timeout=current_app.config["SSH_TIMEOUT"],
            dry_run=dry_run,
            author=current_user.username,
        )
    except (PushError, SshError, RuntimeError) as exc:
        log.message = f"[удаление] {exc}"
        log.domains = ", ".join(selected)
        log.finished_at = datetime.utcnow()
        db.session.add(log)
        db.session.commit()
        flash(f"Удаление из зоны не выполнено: {exc}", "danger")
        return redirect(url_for("fstec.push_log_view", log_id=log.id))
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Непредвиденная ошибка удаления из зоны")
        log.message = f"[удаление] Непредвиденная ошибка: {exc}"
        log.domains = ", ".join(selected)
        log.finished_at = datetime.utcnow()
        db.session.add(log)
        db.session.commit()
        flash(f"Непредвиденная ошибка при удалении: {exc}", "danger")
        return redirect(url_for("fstec.push_log_view", log_id=log.id))

    log.status = result.status
    log.entries_count = len(result.added)
    log.domains = ", ".join(result.added)
    log.backup_path = result.backup_path
    log.old_serial = result.old_serial
    log.new_serial = result.new_serial
    log.message = "[удаление из зоны]\n" + result.log_text
    log.finished_at = datetime.utcnow()
    db.session.add(log)

    if result.status == "success" and result.added:
        for entry in BlockEntry.query.filter(BlockEntry.value.in_(result.added)).all():
            entry.status = STATUS_NEW
            entry.pushed_at = None
    db.session.commit()

    if result.status == PUSH_DRY_RUN:
        flash(
            f"Предпросмотр: будет удалено {len(result.added)} доменов. "
            "Файл зоны не изменялся.",
            "info",
        )
    elif result.added:
        flash(
            f"Удалено из зоны доменов: {len(result.added)}. "
            f"Зона перезагружена, serial {result.old_serial} → {result.new_serial}.",
            "success",
        )
    else:
        flash("Выбранных доменов в зоне нет — изменений не потребовалось.", "info")

    return redirect(url_for("fstec.push_log_view", log_id=log.id))


@fstec_bp.route("/push/history")
@login_required
def push_history():
    logs = PushLog.query.order_by(PushLog.started_at.desc()).all()
    return render_template("fstec/push_history.html", logs=logs)


@fstec_bp.route("/push/history/<int:log_id>")
@login_required
def push_log_view(log_id: int):
    log = db.session.get(PushLog, log_id)
    if not log:
        abort(404)
    return render_template("fstec/push_log.html", log=log)


# --- Настройки SSH (УЗ) ---------------------------------------------------

def _apply_server_form(form, server) -> None:
    server.name = form.name.data
    server.host = form.host.data
    server.port = form.port.data
    server.username = form.username.data
    server.zone_file_path = form.zone_file_path.data
    server.zone_name = form.zone_name.data
    server.use_sudo = form.use_sudo.data
    server.sudo_rndc = form.sudo_rndc.data
    server.validate_zone = form.validate_zone.data
    server.reload_zone = form.reload_zone.data
    server.is_active = form.is_active.data


@fstec_bp.route("/settings", methods=["GET", "POST"])
@operator_required
def settings():
    from ...core.crypto import encrypt

    server = _active_server()
    form = SshServerForm(obj=server)
    app_form = AppSettingsForm(
        protected_domains=get_setting(KEY_PROTECTED)
    )
    def _render():
        return render_template("fstec/settings.html", form=form, app_form=app_form, server=server,
            vt_configured=bool(get_vt_key()),
        )

    # Вторая форма на странице: ключ VirusTotal и защищённые домены.
    if app_form.submit_app.data and app_form.validate_on_submit():
        if app_form.vt_api_key.data:
            set_setting(KEY_VT_API, app_form.vt_api_key.data.strip(), is_secret=True)
        set_setting(KEY_PROTECTED, app_form.protected_domains.data or "")
        db.session.commit()
        flash("Настройки приложения сохранены.", "success")
        return redirect(url_for("fstec.settings"))

    if form.submit.data or form.test.data:
        if not form.validate_on_submit():
            return _render()
        is_new = server is None
        if is_new and not form.password.data:
            flash("Укажите пароль SSH.", "danger")
            return _render()

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
            return _render()

        if is_new:
            server = SshServer()
            db.session.add(server)
        _apply_server_form(form, server)
        if form.password.data:
            server.password_enc = encrypt(form.password.data)
        db.session.commit()
        flash("Настройки SSH сохранены.", "success")
        return redirect(url_for("fstec.settings"))

    return _render()
