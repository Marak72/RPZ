"""SSH-клиент для чтения файла RPZ-зоны с DNS-сервера.

Подключается под учётной записью (логин+пароль), читает файл через SFTP и
гарантированно закрывает соединение. Запись на сервер здесь не выполняется.
"""
import socket

import paramiko

from ..crypto import decrypt


class SshError(Exception):
    """Понятная человеку ошибка SSH-операции для показа во flash-сообщении."""


def read_remote_file(server, timeout: int = 15) -> str:
    """Подключиться по SSH, прочитать файл зоны и вернуть его содержимое.

    server — экземпляр модели SshServer. Пароль хранится зашифрованным и
    расшифровывается здесь непосредственно перед подключением.
    """
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
        sftp = client.open_sftp()
        try:
            with sftp.open(server.zone_file_path, "r") as remote:
                data = remote.read()
        finally:
            sftp.close()
    except paramiko.AuthenticationException as exc:
        raise SshError("Ошибка аутентификации: неверный логин или пароль.") from exc
    except (paramiko.SSHException, socket.error, socket.timeout, OSError) as exc:
        raise SshError(f"Не удалось подключиться или прочитать файл: {exc}") from exc
    finally:
        client.close()

    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def test_connection(server, timeout: int = 15) -> None:
    """Проверить подключение и доступность файла зоны. Бросает SshError при сбое."""
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
        sftp = client.open_sftp()
        try:
            sftp.stat(server.zone_file_path)
        finally:
            sftp.close()
    except paramiko.AuthenticationException as exc:
        raise SshError("Ошибка аутентификации: неверный логин или пароль.") from exc
    except FileNotFoundError as exc:
        raise SshError(
            f"Подключение успешно, но файл {server.zone_file_path} не найден."
        ) from exc
    except (paramiko.SSHException, socket.error, socket.timeout, OSError) as exc:
        raise SshError(f"Не удалось подключиться: {exc}") from exc
    finally:
        client.close()
