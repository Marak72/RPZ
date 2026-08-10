"""Мелкие помощники, общие для всех сервисов портала."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from functools import wraps

from flask import Response, abort
from flask_login import current_user, login_required


def service_guard(service_id: str):
    """Закрыть blueprint сервиса от тех, кому он не выдан.

    Ставится как ``before_request``: страницу нельзя открыть по прямой ссылке,
    даже если её нет в переключателе.
    """

    def check():
        if not current_user.is_authenticated:
            return None  # авторизацией занимается login_required на маршрутах
        if not current_user.can_use(service_id):
            abort(403)
        return None

    return check


def operator_required(view):
    """Доступ только для операторов; менеджеры — только просмотр."""

    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_operator:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def csv_response(filename: str, header: list[str], rows) -> Response:
    """Сформировать CSV-файл (разделитель ';' и BOM — открывается в Excel)."""
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


def fmt_dt(value) -> str:
    return value.strftime("%d.%m.%Y %H:%M") if value else ""
