from pathlib import Path

from app.services.fstec.lib import doc_parser

# Фикстура составлена по реальному письму ФСТЭК: индикаторы на отдельных
# строках, имена вложений/названия ПО/ссылки-источники — внутри предложений.
LETTER = (Path(__file__).parent / "fixtures" / "fstec_letter_sample.txt").read_text(
    encoding="utf-8"
)


def _vals(res, t):
    return {e.value for e in res if e.entry_type == t}


def test_standalone_domain_and_ip_extracted():
    res = doc_parser.extract(LETTER)
    assert "5.252.153.67" in _vals(res, "ip")
    assert "arp-database.com" in _vals(res, "domain")


def test_filenames_and_software_excluded():
    res = doc_parser.extract(LETTER)
    vals = {e.value for e in res}
    for junk in ("contract.bz", "contract.exe", "dr.web", "driver.jpg"):
        assert junk not in vals


def test_reference_domain_fstec_excluded():
    res = doc_parser.extract(LETTER)
    assert "fstec.ru" not in {e.value for e in res}


def test_url_path_does_not_leak_into_domains():
    res = doc_parser.extract(LETTER)
    domains = _vals(res, "domain")
    # путь из URL не должен попасть как домен
    assert "driver.jpg" not in domains
    assert "yulyaigonina" not in domains


def test_host_of_a_url_with_path_is_not_blocked():
    """Хост ссылки с путём — не кандидат на блокировку.

    В письме встречаются github.com/<аккаунт> и telegram.me/<канал>: вредоносна
    страница, а не сервис целиком. RPZ блокирует имя целиком, поэтому выгрузка
    такого хоста закрыла бы отделу легитимный ресурс.
    """
    domains = _vals(doc_parser.extract(LETTER), "domain")
    assert "github.com" not in domains
    assert "telegram.me" not in domains


def test_domain_listed_separately_is_still_blocked():
    """Правило выше не должно спасать по-настоящему вредоносные домены.

    voffice.help приведён в письме и отдельной строкой, и внутри ссылок —
    в блокировку он обязан попасть.
    """
    res = doc_parser.extract(LETTER)
    assert "voffice.help" in _vals(res, "domain")
    assert "http://voffice.help/driver.jpg" in _vals(res, "url")


def test_urls_with_paths_are_separate_category():
    res = doc_parser.extract(LETTER)
    urls = _vals(res, "url")
    assert "http://voffice.help/driver.jpg" in urls
    assert "https://telegram.me/hgo9tx" in urls
    # у URL сохраняется хост — по нему аналитик решает, блокировать ли домен
    entry = next(e for e in res if e.value == "http://voffice.help/driver.jpg")
    assert entry.host == "voffice.help"


def test_url_without_path_is_domain_only():
    """Ссылка без пути — это про домен целиком, его и блокируем."""
    res = doc_parser.extract("hxxps[:]//lorebird[.]com;\n")
    assert _vals(res, "url") == set()
    assert "lorebird.com" in _vals(res, "domain")


def test_bare_url_with_only_trailing_slash_still_blocks_the_domain():
    res = doc_parser.extract("hxxp[:]//evil-shop[.]ru/;\n")
    assert "evil-shop.ru" in _vals(res, "domain")
    assert _vals(res, "url") == set()


def test_is_valid_domain_rejects_file_names():
    assert doc_parser.is_valid_domain("evil.com") is True
    assert doc_parser.is_valid_domain("contract.exe") is False
    assert doc_parser.is_valid_domain("report.docx") is False
    assert doc_parser.is_valid_domain("a.b") is False  # TLD из одного символа
    assert doc_parser.is_valid_domain("-bad.com") is False
    assert doc_parser.is_valid_domain("bad-.com") is False
    assert doc_parser.is_valid_domain("1.2.3.4") is False
    assert doc_parser.is_valid_domain("xn--80affa3aj0al.xn--80asehdb") is True


def test_inline_indicators_after_address_word():
    res = doc_parser.extract(LETTER)
    assert "31.56.209.126" in _vals(res, "ip")
    assert "crystalxrat.net" in _vals(res, "domain")


def test_email_domain_extracted():
    res = doc_parser.extract(LETTER)
    assert "roskomnadsor.ru" in _vals(res, "domain")


def test_hashes_classified_and_lowercased():
    res = doc_parser.extract(LETTER)
    assert "f833236b43cfa6d69b6ceadae649c5c970e6e1b32fd3d3d0e5ccc4faa433e68f" in _vals(res, "sha256")
    assert "2f150acc59944edb992fcccc5e405349" in _vals(res, "md5")
    assert "98d909338f8f49a340bf7a3302b32be8f32f69a9" in _vals(res, "sha1")


def test_refang_basic():
    assert doc_parser.refang("a[.]b") == "a.b"
    assert "https://" in doc_parser.refang("hxxps[:]//x")


def test_valid_ipv4_helper():
    assert doc_parser._valid_ipv4("10.0.0.1") is True
    assert doc_parser._valid_ipv4("256.0.0.1") is False
    assert doc_parser._valid_ipv4("1.2.3") is False


def test_deduplication():
    res = doc_parser.extract("a[.]com;\na[.]com;\nA[.]COM;")
    assert len(_vals(res, "domain")) == 1
