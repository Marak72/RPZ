import pytest

from app.services.fstec.lib import rpz_writer
from app.services.fstec.lib.rpz_writer import PushError

ZONE = """$TTL 60
@   IN  SOA localhost. root.localhost. (
        2026012302
        1H
        15M
        1W
        1H )

    IN  NS  localhost.

browser-sputnik.ru CNAME rpz-drop.
*.browser-sputnik.ru CNAME rpz-drop.
"""


def test_find_serial_multiline_soa():
    assert rpz_writer.find_serial(ZONE) == "2026012302"


def test_find_serial_inline_soa():
    inline = "@ IN SOA ns.example. root.example. 2026010101 3600 900 604800 86400\n"
    assert rpz_writer.find_serial(inline) == "2026010101"


def test_next_serial_same_day_increments_counter():
    assert rpz_writer.next_serial("2026012302", today="20260123") == "2026012303"


def test_next_serial_new_day_resets_counter():
    assert rpz_writer.next_serial("2026012302", today="20260124") == "2026012401"


def test_next_serial_always_increases_when_clock_went_back():
    # «Сегодня» раньше даты в serial — serial всё равно обязан вырасти.
    assert int(rpz_writer.next_serial("2026012302", today="20260101")) > 2026012302


def test_next_serial_counter_overflow():
    assert rpz_writer.next_serial("2026012399", today="20260123") == "2026012400"


def test_replace_serial_only_changes_soa():
    updated = rpz_writer.replace_serial(ZONE, "2026012399")
    assert "2026012399" in updated
    assert "2026012302" not in updated
    # записи блокировок не тронуты
    assert "browser-sputnik.ru CNAME rpz-drop." in updated


def test_build_records_creates_domain_and_wildcard():
    out = rpz_writer.build_records(["evil.com"])
    assert "evil.com CNAME rpz-drop." in out
    assert "*.evil.com CNAME rpz-drop." in out


def test_build_new_content_appends_and_bumps():
    content, old, new = rpz_writer.build_new_content(ZONE, ["evil.com"], "тест")
    assert old == "2026012302"
    assert new != old
    assert new in content
    assert "evil.com CNAME rpz-drop." in content
    assert "; тест" in content
    # существующие записи сохранены
    assert "browser-sputnik.ru CNAME rpz-drop." in content


def test_build_new_content_without_soa_refuses():
    with pytest.raises(PushError):
        rpz_writer.build_new_content("evil.com CNAME rpz-drop.\n", ["x.com"])


def test_validate_domains_filters_junk():
    ok, rejected = rpz_writer.validate_domains(
        ["Evil.COM", "contract.exe", "", "1.2.3.4", "good-site.ru", "evil.com"]
    )
    assert ok == ["evil.com", "good-site.ru"]  # нормализация + дедупликация
    assert "contract.exe" in rejected
    assert "1.2.3.4" in rejected  # IP в RPZ-зону доменов не пишем


class _Srv:
    zone_name = "rpz.block"
    use_sudo = False
    sudo_rndc = False


def test_rndc_command_plain():
    s = _Srv()
    assert rpz_writer.rndc_command(s, "/usr/sbin/rndc") == \
        "/usr/sbin/rndc reload 'rpz.block'"


def test_rndc_command_matches_narrow_sudoers_rule():
    """Команда должна подходить под правило:
    rpzbot ALL=(root) NOPASSWD: /usr/sbin/rndc reload rpz.block
    """
    import shlex

    s = _Srv()
    s.sudo_rndc = True
    cmd = rpz_writer.rndc_command(s, "/usr/sbin/rndc")
    # Никакой обёртки sh -c — иначе узкое правило sudoers не сработает.
    assert "sh -c" not in cmd
    assert cmd.startswith("sudo -n /usr/sbin/rndc reload")
    # После разбора шеллом argv точно совпадает с правилом в sudoers.
    assert shlex.split(cmd) == [
        "sudo", "-n", "/usr/sbin/rndc", "reload", "rpz.block",
    ]


def test_validate_domains_rejects_everything_bad():
    ok, rejected = rpz_writer.validate_domains(["../etc/passwd", "a b c", "-bad-.com"])
    assert ok == []
    assert len(rejected) == 3
