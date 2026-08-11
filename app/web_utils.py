"""Мелкие помощники, общие для всех сервисов портала."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from functools import wraps

from flask import Response, abort
from flask_login import current_user, login_required


#: Через сколько записей длинный цикл закрывает транзакцию.
#: SQLite пускает только одного писателя: пока идёт длинная транзакция,
#: остальные страницы портала не могут сохранить ничего и падают с
#: «database is locked». Дробление держит окно записи коротким.
WRITE_BATCH = 200


def current_url() -> str:
    """Адрес текущей страницы вместе с префиксом подпути.

    ``request.full_path`` префикса не содержит: за обратным прокси он лежит
    в ``script_root``. Подставив full_path в поле возврата, мы отправляли
    браузер мимо приложения — на /tasks/ вместо /soc/tasks/.
    """
    from flask import request

    path = request.full_path
    if path.endswith("?"):
        path = path[:-1]
    return (request.script_root or "") + path


def safe_back(fallback_endpoint: str, given: str = "") -> str:
    """Куда вернуться после действия: только внутрь этого приложения.

    Значение приходит из формы, поэтому чужой адрес игнорируется — иначе
    получился бы открытый редирект наружу.
    """
    from flask import request, url_for

    root = request.script_root or ""
    if given.startswith("/") and not given.startswith("//"):
        # Ссылка без префикса пришла из старой вкладки — дополним.
        if root and not given.startswith(root + "/") and given != root:
            return root + given
        return given
    return url_for(fallback_endpoint)


class LazyCounts:
    """Счётчики, которые считаются только если шаблон их спросил.

    Навигационные счётчики нужны на страницах своего сервиса, а контекстный
    процессор выполняется на каждый запрос. Без ленивости открытие любой
    страницы портала тянуло бы десяток лишних запросов к базе.
    """

    def __init__(self, loader, empty: dict):
        self._loader = loader
        self._empty = empty
        self._data = None

    def _load(self) -> dict:
        if self._data is None:
            try:
                self._data = self._loader()
            except Exception:  # noqa: BLE001 — например, БД ещё не мигрирована
                from flask import current_app

                current_app.logger.exception("Не удалось посчитать счётчики")
                self._data = self._empty
        return self._data

    def __getitem__(self, key):
        return self._load().get(key, 0)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._load().get(name, 0)


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
