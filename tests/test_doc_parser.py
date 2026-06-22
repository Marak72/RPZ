from app.services import doc_parser

# Фрагмент в стиле реального письма ФСТЭК: индикаторы на отдельных строках,
# имена файлов/ПО/ссылки-источники — внутри предложений.
LETTER = """Информирую.
Во вложениях прикреплен архив «Contract.bz», содержащий «Contract.exe».
для антивирусного средства Dr.Web Security Space необходимо использовать.
ограничение обращений к следующим адресам:
5[.]252[.]153[.]67;
arp-database[.]com;
hxxps[:]//github[.]com/yulyaigonina/.
hxxp[:]//voffice[.]help/driver[.]jpg;
обеспечить ограничение обращений к IP-адресу 31[.]56[.]209[.]126, используя.
ограничение обращений к адресу crystalxrat[.]net, используя.
ограничить получение писем с адреса info@roskomnadsor[.]ru.
Методики (https://fstec.ru/dokumenty/vse-dokumenty).
индикаторы компрометации (sha256):
f833236b43cfa6d69b6ceadae649c5c970e6e1b32fd3d3d0e5ccc4faa433e68f;
(md5):
2F150ACC59944EDB992FCCCC5E405349;
(sha1):
98D909338F8F49A340BF7A3302B32BE8F32F69A9.
"""


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


def test_url_host_only_no_path_fragments():
    res = doc_parser.extract(LETTER)
    domains = _vals(res, "domain")
    assert "github.com" in domains
    assert "voffice.help" in domains
    # путь из URL не должен попасть как домен
    assert "driver.jpg" not in domains


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
