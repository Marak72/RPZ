"""Интеграционные тесты выгрузки в RPZ на эмуляторе DNS-сервера.

DNS-сервер боевой, поэтому здесь проверяется главное: при любой ошибке
файл зоны либо не изменяется вовсе, либо восстанавливается из резервной копии.
"""
import shlex

import pytest

from app.services import rpz_writer
from app.services.rpz_writer import PushError

ZONE = """$TTL 60
@   IN  SOA localhost. root.localhost. (
        2026012302
        1H
        15M
        1W
        1H )

    IN  NS  localhost.

existing.ru CNAME rpz-drop.
*.existing.ru CNAME rpz-drop.
"""


class FakeServer:
    host = "10.0.0.5"
    port = 22
    username = "root"
    password_enc = ""
    zone_file_path = "/var/named/master/rpz.block.db"
    zone_name = "rpz.block"
    use_sudo = False
    sudo_rndc = False
    validate_zone = True
    reload_zone = True


class FakeClient:
    """Эмулятор удалённого сервера: файловая система в памяти + команды."""

    def __init__(self, checkzone_fails=False, write_fails=False, reload_fails=False):
        self.files = {FakeServer.zone_file_path: ZONE}
        self.checkzone_fails = checkzone_fails
        self.write_fails = write_fails
        self.reload_fails = reload_fails
        self.commands = []
        self.sudo_calls = []

    # -- эмуляция команд --
    def run(self, command):
        self.commands.append(command)
        argv = shlex.split(command)
        # Снять префикс `sudo -n` (узкий вызов rndc идёт без обёртки sh -c).
        if argv[:2] == ["sudo", "-n"]:
            self.sudo_calls.append(argv[2:])
            argv = argv[2:]
        # Развернуть обёртку `sh -c '<скрипт>'` (её ставит sudo_wrap).
        if argv[:2] == ["sh", "-c"]:
            return self._run_script(argv[-1])
        return self._run_script(shlex.join(argv))

    def _run_script(self, script):
        if "command -v named-checkzone" in script:
            return 0, "/usr/sbin/named-checkzone", ""
        if "command -v rndc" in script:
            return 0, "/usr/sbin/rndc", ""

        # cat <src> > <dst>  (установка нового содержимого / откат)
        if ">" in script:
            left, right = script.split(">", 1)
            src = shlex.split(left)[-1]
            dst = shlex.split(right)[0]
            if self.write_fails and dst == FakeServer.zone_file_path:
                return 1, "", "Permission denied"
            if src not in self.files:
                return 1, "", f"cat: {src}: No such file"
            self.files[dst] = self.files[src]
            return 0, "", ""

        argv = shlex.split(script)
        if not argv:
            return 0, "", ""
        cmd = argv[0].rsplit("/", 1)[-1]

        if cmd == "named-checkzone":
            if self.checkzone_fails:
                return 1, "zone rpz.block/IN: has no NS records", "not loaded"
            zone_file = argv[-1]
            if zone_file not in self.files:
                return 1, "", "file not found"
            return 0, "OK", ""
        if cmd == "rndc":
            if self.reload_fails:
                return 1, "", "rndc: connect failed"
            return 0, "zone reload up-to-date", ""
        if cmd == "cp":
            src, dst = argv[-2], argv[-1]
            if src not in self.files:
                return 1, "", "cp: no such file"
            self.files[dst] = self.files[src]
            return 0, "", ""
        if cmd == "rm":
            for path in argv[2:]:
                self.files.pop(path, None)
            return 0, "", ""
        if cmd == "test":
            return 0, "", ""
        return 0, "", ""


@pytest.fixture
def patched(monkeypatch):
    """Подменить сетевые функции rpz_writer на работу с FakeClient."""
    state = {}

    def _install(client):
        state["client"] = client
        from contextlib import contextmanager

        @contextmanager
        def fake_session(server, timeout=15):
            yield client

        monkeypatch.setattr(rpz_writer, "ssh_session", fake_session)
        monkeypatch.setattr(rpz_writer, "read_file",
                            lambda c, path: c.files[path])
        monkeypatch.setattr(rpz_writer, "write_file",
                            lambda c, path, content: c.files.__setitem__(path, content))
        monkeypatch.setattr(rpz_writer, "run_command",
                            lambda c, cmd, timeout=60: c.run(cmd))
        return client

    return _install


def test_dry_run_does_not_touch_zone(patched):
    client = patched(FakeClient())
    before = client.files[FakeServer.zone_file_path]
    result = rpz_writer.push_domains(FakeServer(), ["evil.com"], dry_run=True)
    assert result.status == "dry_run"
    assert result.added == ["evil.com"]
    assert client.files[FakeServer.zone_file_path] == before  # файл не тронут
    assert "evil.com CNAME rpz-drop." in result.diff


def test_successful_push_updates_zone_and_serial(patched):
    client = patched(FakeClient())
    result = rpz_writer.push_domains(FakeServer(), ["evil.com"])
    assert result.status == "success"
    zone = client.files[FakeServer.zone_file_path]
    assert "evil.com CNAME rpz-drop." in zone
    assert "*.evil.com CNAME rpz-drop." in zone
    assert "existing.ru CNAME rpz-drop." in zone      # старое сохранено
    assert result.new_serial != result.old_serial
    assert result.new_serial in zone
    assert result.backup_path                          # резервная копия создана
    assert client.files[result.backup_path] == ZONE    # и содержит исходник


def test_already_present_domains_are_skipped(patched):
    client = patched(FakeClient())
    result = rpz_writer.push_domains(FakeServer(), ["existing.ru"])
    assert result.added == []
    assert result.skipped == ["existing.ru"]
    assert client.files[FakeServer.zone_file_path] == ZONE  # изменений нет


def test_checkzone_failure_leaves_zone_untouched(patched):
    client = patched(FakeClient(checkzone_fails=True))
    with pytest.raises(PushError, match="Проверка зоны не пройдена"):
        rpz_writer.push_domains(FakeServer(), ["evil.com"])
    # Главное: боевой файл не изменён и резервная копия даже не понадобилась.
    assert client.files[FakeServer.zone_file_path] == ZONE


def test_write_failure_leaves_zone_untouched(patched):
    client = patched(FakeClient(write_fails=True))
    with pytest.raises(PushError):
        rpz_writer.push_domains(FakeServer(), ["evil.com"])
    assert client.files[FakeServer.zone_file_path] == ZONE


def test_reload_failure_triggers_rollback(patched):
    client = patched(FakeClient(reload_fails=True))
    with pytest.raises(PushError):
        rpz_writer.push_domains(FakeServer(), ["evil.com"])
    # После неудачного reload зона восстановлена из резервной копии.
    assert client.files[FakeServer.zone_file_path] == ZONE
    assert any("cat" in c and ".bak-" in c for c in client.commands)


def test_invalid_domains_are_never_written(patched):
    client = patched(FakeClient())
    result = rpz_writer.push_domains(
        FakeServer(), ["good.com", "contract.exe", "1.2.3.4"]
    )
    assert result.added == ["good.com"]
    assert set(result.rejected) == {"contract.exe", "1.2.3.4"}
    zone = client.files[FakeServer.zone_file_path]
    assert "contract.exe" not in zone
    assert "1.2.3.4" not in zone


def test_all_domains_invalid_aborts(patched):
    client = patched(FakeClient())
    with pytest.raises(PushError, match="Нет корректных доменов"):
        rpz_writer.push_domains(FakeServer(), ["contract.exe"])
    assert client.files[FakeServer.zone_file_path] == ZONE


def test_push_with_narrow_sudo_for_rndc_only(patched):
    """Непривилегированная УЗ: права на файл через группу, reload — через sudo.

    Проверяем, что под sudo уходит РОВНО одна команда и ровно в том виде,
    который разрешён правилом sudoers:
        rpzbot ALL=(root) NOPASSWD: /usr/sbin/rndc reload rpz.block
    """
    client = patched(FakeClient())
    server = FakeServer()
    server.sudo_rndc = True

    result = rpz_writer.push_domains(server, ["evil.com"])
    assert result.status == "success"
    assert "evil.com CNAME rpz-drop." in client.files[FakeServer.zone_file_path]

    # Под sudo прошёл только rndc reload — файловые операции выполнены от УЗ.
    assert client.sudo_calls == [["/usr/sbin/rndc", "reload", "rpz.block"]]


def test_remove_domain_from_zone(patched):
    client = patched(FakeClient())
    result = rpz_writer.remove_domains(FakeServer(), ["existing.ru"])
    assert result.status == "success"
    assert result.action == "remove"
    zone = client.files[FakeServer.zone_file_path]
    assert "existing.ru" not in zone
    # Служебные строки зоны остались нетронутыми.
    assert "SOA" in zone and "$TTL" in zone and "NS" in zone
    assert result.new_serial != result.old_serial


def test_remove_missing_domain_changes_nothing(patched):
    client = patched(FakeClient())
    result = rpz_writer.remove_domains(FakeServer(), ["absent.com"])
    assert result.skipped == ["absent.com"]
    assert client.files[FakeServer.zone_file_path] == ZONE


def test_remove_dry_run_does_not_touch_zone(patched):
    client = patched(FakeClient())
    result = rpz_writer.remove_domains(FakeServer(), ["existing.ru"], dry_run=True)
    assert result.status == "dry_run"
    assert client.files[FakeServer.zone_file_path] == ZONE


def test_remove_rolls_back_on_reload_failure(patched):
    client = patched(FakeClient(reload_fails=True))
    with pytest.raises(PushError):
        rpz_writer.remove_domains(FakeServer(), ["existing.ru"])
    assert client.files[FakeServer.zone_file_path] == ZONE


def test_protected_domains_are_never_pushed(patched):
    client = patched(FakeClient())
    result = rpz_writer.push_domains(
        FakeServer(), ["evil.com", "gosuslugi.ru"], protected={"gosuslugi.ru"}
    )
    assert result.added == ["evil.com"]
    assert "gosuslugi.ru" in result.rejected
    assert "gosuslugi.ru" not in client.files[FakeServer.zone_file_path]


def test_temp_file_is_cleaned_up(patched):
    client = patched(FakeClient())
    rpz_writer.push_domains(FakeServer(), ["evil.com"])
    assert any(c.startswith("rm -f") for c in client.commands)
