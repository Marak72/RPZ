from app.services.fstec.lib import rpz_parser

SAMPLE = """$TTL 60
@   IN  SOA localhost. root.localhost. (
        2026012302
        1H
        15M
        1W
        1H )

    IN  NS  localhost.

test-bad.example      A   91.200.84.212
*.test-bad.example    A   91.200.84.212
qwer.bad.ru	A	91.200.84.212
browser-sputnik.ru CNAME rpz-drop.
*.browser-sputnik.ru CNAME rpz-drop.
rpm-bin.link CNAME rpz-drop.
*.rpm-bin.link CNAME rpz-drop.
lib.rpm-bin.link CNAME rpz-drop.
*.lib.rpm-bin.link CNAME rpz-drop.
"""


def test_header_is_skipped():
    entries = rpz_parser.parse(SAMPLE)
    domains = {e.domain for e in entries}
    # никаких служебных записей зоны
    assert "localhost" not in domains
    assert all(e.record_type in ("A", "CNAME") for e in entries)


def test_a_record_is_redirect():
    entries = rpz_parser.parse(SAMPLE)
    a = [e for e in entries if e.domain == "test-bad.example" and not e.is_wildcard][0]
    assert a.record_type == "A"
    assert a.target == "91.200.84.212"
    assert a.action == "redirect"


def test_cname_rpz_drop_is_block():
    entries = rpz_parser.parse(SAMPLE)
    c = [e for e in entries if e.domain == "browser-sputnik.ru" and not e.is_wildcard][0]
    assert c.record_type == "CNAME"
    assert c.action == "block"


def test_wildcard_detection():
    entries = rpz_parser.parse(SAMPLE)
    wilds = {e.domain for e in entries if e.is_wildcard}
    assert "browser-sputnik.ru" in wilds
    assert "rpm-bin.link" in wilds


def test_grouping_combines_base_and_wildcard():
    entries = rpz_parser.parse(SAMPLE)
    rows = rpz_parser.group_by_domain(entries)
    row = [r for r in rows if r["domain"] == "browser-sputnik.ru"][0]
    assert row["has_base"] is True
    assert row["has_wildcard"] is True
    assert row["action"] == "block"


def test_tab_separated_line():
    entries = rpz_parser.parse(SAMPLE)
    assert any(e.domain == "qwer.bad.ru" for e in entries)
