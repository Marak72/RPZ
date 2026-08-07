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
    action: str = "add"              # add / remove
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


def rndc_command(server, rndc_path: str) -> str:
    """Собрать команду перезагрузки зоны.

    rndc вызывается НАПРЯМУЮ (без обёртки `sh -c`), чтобы подходило узкое
    правило в sudoers, разрешающее ровно одну команду:

        rpzbot ALL=(root) NOPASSWD: /usr/sbin/rndc reload rpz.block
    """
    command = f"{rndc_path} reload {shell_quote(server.zone_name)}"
    if getattr(server, "sudo_rndc", False) or getattr(server, "use_sudo", False):
        return f"sudo -n {command}"
    return command


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



def remove_records(content: str, domains) -> tuple[str, int]:
    """Убрать из зоны все записи указанных доменов (и их wildcard-варианты).

    Возвращает (новое содержимое, число удалённых строк). Служебные строки
    зоны (SOA, NS, $TTL) не затрагиваются никогда.
    """
    targets = {(d or "").strip().lower().rstrip(".") for d in domains if d}
    kept: list[str] = []
    removed = 0
    for line in content.splitlines():
        stripped = line.strip()
        tokens = stripped.split()
        drop = False
        if tokens and not stripped.startswith((";", "$", "@")):
            rest = tokens[1:]
            if rest and rest[0].upper() == "IN":
                rest = rest[1:]
            if rest and rest[0].upper() in ("A", "CNAME"):
                name = tokens[0]
                if name.startswith("*."):
                    name = name[2:]
                if name.rstrip(".").lower() in targets:
                    drop = True
        if drop:
            removed += 1
        else:
            kept.append(line)
    new_content = "\n".join(kept)
    if content.endswith("\n") and not new_content.endswith("\n"):
        new_content += "\n"
    return new_content, removed


# --- Общая безопасная процедура изменения зоны -----------------------------

def _apply_zone_change(server, timeout, dry_run, result, transform, verify):
    """Выполнить изменение зоны по безопасной процедуре.

    transform(current, result) -> новое содержимое либо None, если менять нечего.
    verify(after, result) -> текст ошибки либо None, если всё в порядке.
    """
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    tmp_path = f"/tmp/rpz-fstec-{stamp}.db"
    zone = server.zone_file_path
    backup_path = f"{zone}.bak-{stamp}"

    with ssh_session(server, timeout) as client:
        current = read_file(client, zone)
        result.steps.append(f"Прочитан файл зоны {zone} ({len(current)} байт)")

        new_content = transform(current, result)
        if new_content is None:
            result.status = "dry_run" if dry_run else "success"
            return result

        write_file(client, tmp_path, new_content)
        result.steps.append(f"Новая версия зоны загружена во временный файл {tmp_path}")

        try:
            # Проверка синтаксиса до любых изменений боевого файла.
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
                result.steps.append(
                    f"named-checkzone: OK ({out.splitlines()[-1] if out else 'ok'})"
                )
            else:
                result.steps.append(
                    "ВНИМАНИЕ: проверка named-checkzone отключена в настройках"
                )

            if dry_run:
                result.status = "dry_run"
                result.steps.append("Режим предпросмотра: боевой файл не изменялся.")
                return result

            # Резервная копия боевого файла.
            rc, _, err = run_command(
                client,
                sudo_wrap(server, f"cp -p {shell_quote(zone)} {shell_quote(backup_path)}"),
                timeout=timeout,
            )
            if rc != 0:
                raise PushError(f"Не удалось создать резервную копию зоны: {err}")
            result.backup_path = backup_path
            result.steps.append(f"Создана резервная копия: {backup_path}")

            # Установка нового содержимого (сохраняет владельца, права, SELinux).
            rc, _, err = run_command(
                client,
                sudo_wrap(server, f"cat {shell_quote(tmp_path)} > {shell_quote(zone)}"),
                timeout=timeout,
            )
            if rc != 0:
                raise PushError(f"Не удалось записать файл зоны: {err}")
            result.steps.append("Новое содержимое установлено в файл зоны")

            # Перезагрузка зоны.
            if server.reload_zone:
                rndc = _find_binary(client, "rndc")
                if not rndc:
                    raise PushError(
                        "На сервере не найден rndc — не удалось перезагрузить зону."
                    )
                rc, out, err = run_command(
                    client, rndc_command(server, rndc), timeout=timeout
                )
                if rc != 0:
                    raise PushError(
                        f"rndc reload завершился с ошибкой: {out} {err}".strip()
                    )
                result.steps.append(f"rndc reload: {out or 'OK'}")

            # Контрольная проверка результата.
            after = read_file(client, zone)
            problem = verify(after, result)
            if problem:
                raise PushError(problem)
            result.steps.append("Проверка после записи пройдена")

            result.status = "success"
            return result

        except (PushError, SshError) as exc:
            result.error = str(exc)
            if result.backup_path:
                result.steps.append(f"ОШИБКА: {exc}")
                ok = _rollback(client, server, backup_path, timeout, result)
                result.status = "rolled_back" if ok else "failed"
            else:
                result.status = "failed"
                result.steps.append(f"ОШИБКА (боевой файл не изменялся): {exc}")
            raise PushError(result.error) from exc

        finally:
            run_command(client, f"rm -f {shell_quote(tmp_path)}", timeout=timeout)


# --- Добавление доменов ----------------------------------------------------

def push_domains(
    server,
    domains,
    timeout: int = 30,
    dry_run: bool = False,
    author: str = "",
    protected: set | None = None,
) -> PushResult:
    """Добавить домены в RPZ-зону. При dry_run боевой файл не изменяется."""
    result = PushResult(status="dry_run" if dry_run else "failed", action="add")
    valid, rejected = validate_domains(domains)

    # Защищённые домены не должны попасть в блокировку ни при каких условиях.
    if protected:
        blocked_by_policy = [d for d in valid if d in protected]
        if blocked_by_policy:
            rejected.extend(blocked_by_policy)
            valid = [d for d in valid if d not in protected]
            result.steps.append(
                "Отклонены защищённые домены: " + ", ".join(blocked_by_policy)
            )

    result.rejected = rejected
    if rejected:
        result.steps.append(f"Отклонено некорректных значений: {len(rejected)}")
    if not valid:
        raise PushError("Нет корректных доменов для выгрузки.")

    to_add: list[str] = []

    def transform(current, res):
        existing = {e.domain for e in rpz_parser.parse(current)}
        to_add.extend(d for d in valid if d not in existing)
        res.skipped = [d for d in valid if d in existing]
        if res.skipped:
            res.steps.append(f"Уже в зоне, пропущено: {len(res.skipped)}")
        if not to_add:
            res.steps.append("Новых доменов нет — изменения не требуются.")
            return None
        res.added = list(to_add)
        comment = (
            f"добавлено ФСТЭК-РПЗ {datetime.now().strftime('%d.%m.%Y %H:%M')}"
            + (f" ({author})" if author else "")
        )
        content, old_serial, new_serial = build_new_content(current, to_add, comment)
        res.old_serial, res.new_serial = old_serial, new_serial
        res.diff = build_records(to_add, comment)
        res.steps.append(f"Serial: {old_serial} → {new_serial}")
        res.steps.append(
            f"Будет добавлено доменов: {len(to_add)} "
            f"({len(to_add) * 2} записей с учётом wildcard)"
        )
        return content

    def verify(after, res):
        after_domains = {e.domain for e in rpz_parser.parse(after)}
        missing = [d for d in to_add if d not in after_domains]
        if missing:
            return f"После записи в зоне отсутствуют домены: {', '.join(missing[:5])}"
        if find_serial(after) != res.new_serial:
            return "После записи serial зоны не соответствует ожидаемому."
        return None

    return _apply_zone_change(server, timeout, dry_run, result, transform, verify)


# --- Удаление доменов ------------------------------------------------------

def remove_domains(
    server,
    domains,
    timeout: int = 30,
    dry_run: bool = False,
    author: str = "",
) -> PushResult:
    """Удалить домены из RPZ-зоны (снять блокировку) по той же процедуре."""
    result = PushResult(status="dry_run" if dry_run else "failed", action="remove")
    wanted = [(d or "").strip().lower().rstrip(".") for d in domains if (d or "").strip()]
    if not wanted:
        raise PushError("Не указано ни одного домена для удаления.")

    removed_domains: list[str] = []

    def transform(current, res):
        existing = {e.domain for e in rpz_parser.parse(current)}
        removed_domains.extend(d for d in wanted if d in existing)
        res.skipped = [d for d in wanted if d not in existing]
        if res.skipped:
            res.steps.append(f"В зоне отсутствуют, пропущено: {len(res.skipped)}")
        if not removed_domains:
            res.steps.append("Указанных доменов в зоне нет — изменения не требуются.")
            return None

        content, removed_lines = remove_records(current, removed_domains)
        old_serial = find_serial(content)
        if not old_serial:
            raise PushError("В файле зоны не найден serial (SOA). Удаление отменено.")
        new_serial = next_serial(old_serial)
        content = replace_serial(content, new_serial)
        res.added = list(removed_domains)   # для журнала: какие домены затронуты
        res.old_serial, res.new_serial = old_serial, new_serial
        res.diff = "\n".join(f"- {d}" for d in removed_domains)
        res.steps.append(f"Serial: {old_serial} → {new_serial}")
        res.steps.append(
            f"Будет удалено доменов: {len(removed_domains)} "
            f"({removed_lines} строк зоны)"
        )
        return content

    def verify(after, res):
        after_domains = {e.domain for e in rpz_parser.parse(after)}
        still = [d for d in removed_domains if d in after_domains]
        if still:
            return f"После записи в зоне остались домены: {', '.join(still[:5])}"
        if find_serial(after) != res.new_serial:
            return "После записи serial зоны не соответствует ожидаемому."
        return None

    return _apply_zone_change(server, timeout, dry_run, result, transform, verify)


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
            run_command(client, rndc_command(server, rndc), timeout=timeout)
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
