"""Безопасная выгрузка новых доменов в RPZ-зону BIND на боевом DNS-сервере.

DNS-сервер боевой, поэтому процедура построена так, чтобы её нельзя было
сломать необратимо. Порядок шагов:

  1. Прочитать текущий файл зоны и разобрать его.
  2. Отфильтровать домены, которые уже есть в зоне (идемпотентность).
  3. Проверить каждый домен строгой валидацией — в зону не может попасть мусор.
  4. Собрать НОВОЕ содержимое локально: инкремент serial в SOA + новые записи.
  5. Загрузить его во ВРЕМЕННЫЙ файл на сервере (боевой файл ещё не тронут).
  6. Проверить временный файл через `named-checkzone` — если синтаксис плохой,
     процедура прекращается, боевой файл остаётся нетронутым.
  7. Сделать резервную копию боевого файла рядом (zone.db.bak-<метка времени>).
  8. Установить новое содержимое через `cat tmp > zone` — файл сохраняет
     владельца, права и контекст SELinux (в отличие от mv/cp).
  9. `rndc reload <зона>` и проверка, что зона перечиталась.
 10. Любая ошибка после шага 8 → автоматический откат из резервной копии
     и повторный reload.

Также поддерживается режим предпросмотра (dry-run): выполняются шаги 1–6,
показывается точный дифф, но боевой файл не изменяется.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from . import rpz_parser
from .doc_parser import is_valid_domain
from .ssh_client import (
    SshError,
    read_file,
    run_command,
    shell_quote,
    ssh_session,
    sudo_wrap,
    write_file,
)

# Цель CNAME для блокировки — как в существующей зоне пользователя.
BLOCK_TARGET = "rpz-drop."

# SOA с круглыми скобками (многострочный) — serial это первое число после «(».
_SOA_PARENS_RE = re.compile(r"(SOA\b[^\n(]*\(\s*)(\d+)", re.IGNORECASE)
# SOA без скобок — serial это третий токен после SOA.
_SOA_INLINE_RE = re.compile(r"(SOA\s+\S+\s+\S+\s+)(\d+)", re.IGNORECASE)


class PushError(Exception):
    """Ошибка выгрузки, безопасная для показа оператору."""


@dataclass
class PushResult:
    status: str                      # success / dry_run / failed / rolled_back
    added: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    old_serial: str = ""
    new_serial: str = ""
    backup_path: str = ""
    steps: list[str] = field(default_factory=list)
    diff: str = ""
    error: str = ""

    @property
    def log_text(self) -> str:
        return "\n".join(self.steps)


# --- Работа с содержимым зоны (чистые функции, тестируются без сети) -------

def find_serial(content: str) -> str:
    """Найти текущий serial в SOA. Пустая строка, если не найден."""
    for regex in (_SOA_PARENS_RE, _SOA_INLINE_RE):
        m = regex.search(content)
        if m:
            return m.group(2)
    return ""


def next_serial(old: str, today: str | None = None) -> str:
    """Вычислить следующий serial.

    Для формата YYYYMMDDNN — увеличиваем счётчик за сегодня, иначе начинаем
    новый день с 01. Для прочих форматов просто +1. Результат всегда больше
    старого значения (требование BIND).
    """
    today = today or datetime.now().strftime("%Y%m%d")
    if len(old) == 10 and old.isdigit():
        day, counter = old[:8], int(old[8:])
        if day == today:
            if counter < 99:
                return f"{day}{counter + 1:02d}"
            return str(int(old) + 1)  # переполнение счётчика за день
        candidate = f"{today}01"
        # Защита от перевода часов назад: serial обязан расти.
        if int(candidate) > int(old):
            return candidate
        return str(int(old) + 1)
    if old.isdigit():
        return str(int(old) + 1)
    raise PushError(f"Не удалось разобрать serial зоны: {old!r}")


def replace_serial(content: str, new_serial: str) -> str:
    """Заменить serial в SOA на новый (только первое вхождение)."""
    for regex in (_SOA_PARENS_RE, _SOA_INLINE_RE):
        if regex.search(content):
            return regex.sub(lambda m: m.group(1) + new_serial, content, count=1)
    raise PushError("В файле зоны не найдена запись SOA — выгрузка отменена.")


def build_records(domains: list[str], comment: str = "") -> str:
    """Сформировать строки RPZ для списка доменов (домен + wildcard)."""
    lines: list[str] = []
    if comment:
        lines.append(f"; {comment}")
    for domain in domains:
        lines.append(f"{domain} CNAME {BLOCK_TARGET}")
        lines.append(f"*.{domain} CNAME {BLOCK_TARGET}")
    return "\n".join(lines)


def build_new_content(
    current: str, domains: list[str], comment: str = ""
) -> tuple[str, str, str]:
    """Собрать новое содержимое зоны. Возвращает (контент, old_serial, new_serial)."""
    old_serial = find_serial(current)
    if not old_serial:
        raise PushError(
            "В файле зоны не найден serial (SOA). Выгрузка отменена ради безопасности."
        )
    new = next_serial(old_serial)
    content = replace_serial(current, new)
    if not content.endswith("\n"):
        content += "\n"
    content += build_records(domains, comment) + "\n"
    return content, old_serial, new


def validate_domains(domains) -> tuple[list[str], list[str]]:
    """Разделить домены на корректные и отклонённые (в зону пишем только чистые)."""
    ok: list[str] = []
    rejected: list[str] = []
    for raw in domains:
        value = (raw or "").strip().lower().rstrip(".")
        if value and is_valid_domain(value):
            if value not in ok:
                ok.append(value)
        else:
            rejected.append(raw)
    return ok, rejected


# --- Выгрузка на сервер ----------------------------------------------------

def push_domains(
    server,
    domains,
    timeout: int = 30,
    dry_run: bool = False,
    author: str = "",
) -> PushResult:
    """Выгрузить домены в RPZ-зону. При dry_run боевой файл не изменяется."""
    result = PushResult(status="dry_run" if dry_run else "failed")
    valid, rejected = validate_domains(domains)
    result.rejected = rejected
    if rejected:
        result.steps.append(f"Отклонено некорректных значений: {len(rejected)}")
    if not valid:
        raise PushError("Нет корректных доменов для выгрузки.")

    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    tmp_path = f"/tmp/rpz-fstec-{stamp}.db"
    zone = server.zone_file_path
    backup_path = f"{zone}.bak-{stamp}"

    with ssh_session(server, timeout) as client:
        # 1. Прочитать текущую зону.
        current = read_file(client, zone)
        result.steps.append(f"Прочитан файл зоны {zone} ({len(current)} байт)")

        # 2. Отфильтровать уже присутствующие домены.
        existing = {e.domain for e in rpz_parser.parse(current)}
        to_add = [d for d in valid if d not in existing]
        result.skipped = [d for d in valid if d in existing]
        if result.skipped:
            result.steps.append(f"Уже в зоне, пропущено: {len(result.skipped)}")
        if not to_add:
            result.status = "dry_run" if dry_run else "success"
            result.steps.append("Новых доменов нет — изменения не требуются.")
            result.added = []
            return result
        result.added = to_add

        # 3-4. Собрать новое содержимое с инкрементом serial.
        comment = (
            f"добавлено ФСТЭК-РПЗ {datetime.now().strftime('%d.%m.%Y %H:%M')}"
            + (f" ({author})" if author else "")
        )
        new_content, old_serial, new_serial = build_new_content(current, to_add, comment)
        result.old_serial, result.new_serial = old_serial, new_serial
        result.diff = build_records(to_add, comment)
        result.steps.append(f"Serial: {old_serial} → {new_serial}")
        result.steps.append(f"Будет добавлено доменов: {len(to_add)} "
                            f"({len(to_add) * 2} записей с учётом wildcard)")

        # 5. Загрузить во временный файл (боевой файл ещё не тронут).
        write_file(client, tmp_path, new_content)
        result.steps.append(f"Новая версия зоны загружена во временный файл {tmp_path}")

        try:
            # 6. Проверка синтаксиса зоны.
            if server.validate_zone:
                checkzone = _find_binary(client, "named-checkzone")
                if not checkzone:
                    raise PushError(
                        "На сервере не найден named-checkzone. Установите bind-utils "
                        "или отключите проверку зоны в настройках (не рекомендуется)."
                    )
                rc, out, err = run_command(
                    client,
                    f"{checkzone} {shell_quote(server.zone_name)} {shell_quote(tmp_path)}",
                    timeout=timeout,
                )
                if rc != 0:
                    raise PushError(
                        "Проверка зоны не пройдена — боевой файл НЕ изменён.\n"
                        f"{out}\n{err}".strip()
                    )
                result.steps.append(f"named-checkzone: OK ({out.splitlines()[-1] if out else 'ok'})")
            else:
                result.steps.append("ВНИМАНИЕ: проверка named-checkzone отключена в настройках")

            if dry_run:
                result.status = "dry_run"
                result.steps.append("Режим предпросмотра: боевой файл не изменялся.")
                return result

            # 7. Резервная копия боевого файла.
            rc, _, err = run_command(
                client,
                sudo_wrap(server, f"cp -p {shell_quote(zone)} {shell_quote(backup_path)}"),
                timeout=timeout,
            )
            if rc != 0:
                raise PushError(f"Не удалось создать резервную копию зоны: {err}")
            result.backup_path = backup_path
            result.steps.append(f"Создана резервная копия: {backup_path}")

            # 8. Установка нового содержимого с сохранением владельца/прав/SELinux.
            rc, _, err = run_command(
                client,
                sudo_wrap(server, f"cat {shell_quote(tmp_path)} > {shell_quote(zone)}"),
                timeout=timeout,
            )
            if rc != 0:
                raise PushError(f"Не удалось записать файл зоны: {err}")
            result.steps.append("Новое содержимое установлено в файл зоны")

            # 9. Перезагрузка зоны.
            if server.reload_zone:
                rndc = _find_binary(client, "rndc")
                if not rndc:
                    raise PushError("На сервере не найден rndc — не удалось перезагрузить зону.")
                rc, out, err = run_command(
                    client,
                    sudo_wrap(server, f"{rndc} reload {shell_quote(server.zone_name)}"),
                    timeout=timeout,
                )
                if rc != 0:
                    raise PushError(f"rndc reload завершился с ошибкой: {out} {err}".strip())
                result.steps.append(f"rndc reload: {out or 'OK'}")

            # 10. Контрольная проверка: перечитать зону и убедиться в наличии записей.
            after = read_file(client, zone)
            after_domains = {e.domain for e in rpz_parser.parse(after)}
            missing = [d for d in to_add if d not in after_domains]
            if missing:
                raise PushError(
                    f"После записи в зоне отсутствуют домены: {', '.join(missing[:5])}"
                )
            if find_serial(after) != new_serial:
                raise PushError("После записи serial зоны не соответствует ожидаемому.")
            result.steps.append("Проверка после записи: все домены на месте, serial обновлён")

            result.status = "success"
            return result

        except (PushError, SshError) as exc:
            # Откат, если боевой файл уже был изменён.
            result.error = str(exc)
            if result.backup_path:
                result.steps.append(f"ОШИБКА: {exc}")
                rollback_ok = _rollback(client, server, backup_path, timeout, result)
                result.status = "rolled_back" if rollback_ok else "failed"
            else:
                result.status = "failed"
                result.steps.append(f"ОШИБКА (боевой файл не изменялся): {exc}")
            raise PushError(result.error) from exc

        finally:
            run_command(client, f"rm -f {shell_quote(tmp_path)}", timeout=timeout)


def _rollback(client, server, backup_path: str, timeout: int, result: PushResult) -> bool:
    """Восстановить зону из резервной копии и перезагрузить её."""
    zone = server.zone_file_path
    rc, _, err = run_command(
        client,
        sudo_wrap(server, f"cat {shell_quote(backup_path)} > {shell_quote(zone)}"),
        timeout=timeout,
    )
    if rc != 0:
        result.steps.append(
            f"КРИТИЧНО: откат не удался ({err}). "
            f"Восстановите вручную: cp {backup_path} {zone}"
        )
        return False
    result.steps.append(f"Выполнен откат из резервной копии {backup_path}")
    if server.reload_zone:
        rndc = _find_binary(client, "rndc")
        if rndc:
            run_command(
                client,
                sudo_wrap(server, f"{rndc} reload {shell_quote(server.zone_name)}"),
                timeout=timeout,
            )
            result.steps.append("Зона перезагружена после отката")
    return True


def _find_binary(client, name: str) -> str:
    """Найти путь к утилите на сервере (учитывая, что sbin может быть не в PATH)."""
    rc, out, _ = run_command(
        client,
        f"command -v {name} || command -v /usr/sbin/{name} || command -v /sbin/{name}",
    )
    if rc == 0 and out:
        return out.splitlines()[0].strip()
    return ""
