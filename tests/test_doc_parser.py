from app.services import doc_parser


def test_extract_plain_domains_and_ips():
    text = "Заблокировать: example.com, bad-site.ru и адрес 91.200.84.212."
    out = {e.value: e.entry_type for e in doc_parser.extract(text)}
    assert out["example.com"] == "domain"
    assert out["bad-site.ru"] == "domain"
    assert out["91.200.84.212"] == "ip"


def test_refang_defanged_indicators():
    text = "hxxp://evil[.]com и hxxps://bad[.]example[.]org"
    values = {e.value for e in doc_parser.extract(text)}
    assert "evil.com" in values
    assert "bad.example.org" in values


def test_invalid_ip_is_not_extracted_as_ip():
    text = "999.999.1.1"
    out = [e for e in doc_parser.extract(text) if e.entry_type == "ip"]
    assert out == []


def test_deduplication():
    text = "example.com example.com EXAMPLE.com"
    domains = [e for e in doc_parser.extract(text) if e.entry_type == "domain"]
    assert len(domains) == 1


def test_valid_ipv4_helper():
    assert doc_parser._valid_ipv4("10.0.0.1") is True
    assert doc_parser._valid_ipv4("256.0.0.1") is False
    assert doc_parser._valid_ipv4("1.2.3") is False
