"""SSH-клиент для работы с файлом RPZ-зоны на DNS-сервере.

Подключение по логину+паролю. Используется как для чтения зоны, так и для
безопасной выгрузки новых записей (см. rpz_writer.py). Соединение всегда
закрывается вызывающей стороной либо контекстным менеджером.
"""
from __future__ import annotations

import socket
from contextlib import contextmanager

import paramiko

from ..crypto import decrypt


class SshError(Exception):
    """Понятная человеку ошибка SSH-операции для показа во flash-сообщении."""


def _connect(server, timeout: int) -> paramiko.SSHClient:
    password = decrypt(server.password_enc)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=server.host,
            port=server.port,
            username=server.username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
    except paramiko.AuthenticationException as exc:
        client.close()
        raise SshError("Ошибка аутентификации: неверный логин или пароль.") from exc
    except (paramiko.SSHException, socket.error, socket.timeout, OSError) as exc:
        client.close()
        raise SshError(f"Не удалось подключиться к {server.host}: {exc}") from exc
    return client


@contextmanager
def ssh_session(server, timeout: int = 15):
    """Контекстный менеджер: открывает SSH-сессию и гарантированно закрывает её."""
    client = _connect(server, timeout)
    try:
        yield client
    finally:
        client.close()


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 60):
    """Выполнить команду. Возвращает (код возврата, stdout, stderr)."""
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out.strip(), err.strip()
    except (paramiko.SSHException, socket.error, socket.timeout, OSError) as exc:
        raise SshError(f"Ошибка выполнения команды на сервере: {exc}") from exc


def sudo_wrap(server, command: str) -> str:
    """Обернуть команду в sudo -n, если так настроена учётная запись."""
    if getattr(server, "use_sudo", False):
        return f"sudo -n sh -c {shell_quote(command)}"
    return f"sh -c {shell_quote(command)}"


def shell_quote(value: str) -> str:
    """Безопасное экранирование строки для передачи в шелл."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def read_file(client: paramiko.SSHClient, path: str) -> str:
    """Прочитать удалённый файл через SFTP."""
    sftp = client.open_sftp()
    try:
        with sftp.open(path, "r") as remote:
            data = remote.read()
    except FileNotFoundError as exc:
        raise SshError(f"Файл {path} не найден на сервере.") from exc
    except (paramiko.SSHException, OSError) as exc:
        raise SshError(f"Не удалось прочитать {path}: {exc}") from exc
    finally:
        sftp.close()
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data


def write_file(client: paramiko.SSHClient, path: str, content: str) -> None:
    """Записать удалённый файл через SFTP (используется для временных файлов)."""
    sftp = client.open_sftp()
    try:
        with sftp.open(path, "w") as remote:
            remote.write(content)
    except (paramiko.SSHException, OSError) as exc:
        raise SshError(f"Не удалось записать {path}: {exc}") from exc
    finally:
        sftp.close()


def read_remote_file(server, timeout: int = 15) -> str:
    """Подключиться по SSH, прочитать файл зоны и вернуть его содержимое."""
    with ssh_session(server, timeout) as client:
        return read_file(client, server.zone_file_path)


def test_connection(server, timeout: int = 15) -> dict:
    """Проверить подключение и готовность сервера к выгрузке.

    Возвращает словарь с результатами проверок (для показа оператору).
    Бросает SshError, если подключиться или прочитать зону не удалось.
    """
    checks: dict[str, str] = {}
    with ssh_session(server, timeout) as client:
        sftp = client.open_sftp()
        try:
            stat = sftp.stat(server.zone_file_path)
            checks["zone_file"] = f"найден, {stat.st_size} байт"
        except FileNotFoundError as exc:
            raise SshError(
                f"Подключение успешно, но файл {server.zone_file_path} не найден."
            ) from exc
        finally:
            sftp.close()

        # Право на запись в файл зоны (нужно для выгрузки).
        rc, _, _ = run_command(client, sudo_wrap(server, f"test -w {shell_quote(server.zone_file_path)}"))
        checks["write_access"] = "есть" if rc == 0 else "НЕТ (выгрузка не сработает)"

        # Наличие named-checkzone.
        rc, out, _ = run_command(client, "command -v named-checkzone || command -v /usr/sbin/named-checkzone")
        checks["named_checkzone"] = out if rc == 0 and out else "не найден"

        # Наличие rndc.
        rc, out, _ = run_command(client, "command -v rndc || command -v /usr/sbin/rndc")
        rndc_path = out.splitlines()[0].strip() if rc == 0 and out else ""
        checks["rndc"] = rndc_path or "не найден"

        if getattr(server, "use_sudo", False):
            rc, _, err = run_command(client, "sudo -n true")
            checks["sudo"] = "работает без пароля" if rc == 0 else f"НЕ работает: {err}"

        # Разрешена ли ровно та команда reload, которую будет выполнять приложение.
        # `sudo -l <команда>` только ПРОВЕРЯЕТ право, ничего не выполняя.
        if getattr(server, "sudo_rndc", False) and rndc_path:
            rc, _, err = run_command(
                client,
                f"sudo -n -l {rndc_path} reload {shell_quote(server.zone_name)}",
            )
            checks["sudo_rndc"] = (
                "разрешён без пароля"
                if rc == 0
                else f"НЕ разрешён — проверьте sudoers ({err})"
            )

    return checks
