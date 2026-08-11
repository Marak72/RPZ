"""Корневые домены и правила исключений — чистые функции.

Сеть и база не задействуются: проверяется только разбор имён.
"""
from app.services import domains as dm


# --- корневой домен -------------------------------------------------------

def test_random_subdomains_fold_into_one_root():
    """Ради этого свёртка и нужна: сотня имён одного сервиса — одна строка."""
    assert dm.registrable("si21if1u2.afd.footprintdns.com") == "footprintdns.com"
    assert dm.registrable("afd.footprintdns.com") == "footprintdns.com"
    assert dm.registrable("footprintdns.com") == "footprintdns.com"


def test_two_label_domain_is_its_own_root():
    assert dm.registrable("obltub.ru") == "obltub.ru"


def test_regional_ru_suffix_keeps_three_labels():
    """tyumen.ru — суффикс, под которым регистрируют, а не чей-то домен."""
    assert dm.registrable("mail.dept.company.tyumen.ru") == "company.tyumen.ru"
    assert dm.registrable("company.tyumen.ru") == "company.tyumen.ru"
    assert dm.registrable("a.b.gov.ru") == "b.gov.ru"


def test_foreign_multi_label_suffix():
    assert dm.registrable("a.b.example.co.uk") == "example.co.uk"


def test_ip_address_is_not_folded():
    assert dm.registrable("10.61.50.40") == "10.61.50.40"


def test_case_and_trailing_dot_do_not_matter():
    assert dm.registrable("WWW.Example.COM.") == "example.com"


def test_subdomain_part_is_what_differs():
    assert dm.subdomain_part("si21if1u2.afd.footprintdns.com") == "si21if1u2.afd"
    assert dm.subdomain_part("footprintdns.com") == ""


# --- правила исключений ---------------------------------------------------

def test_wildcard_covers_subdomains_and_the_apex():
    """Оператор, исключающий сервис, имеет в виду его целиком."""
    assert dm.matches("*.footprintdns.com", "si21if1u2.afd.footprintdns.com")
    assert dm.matches("*.footprintdns.com", "footprintdns.com")


def test_wildcard_respects_the_label_boundary():
    """Иначе *.footprintdns.com поймал бы чужой evilfootprintdns.com."""
    assert not dm.matches("*.footprintdns.com", "evilfootprintdns.com")


def test_exact_rule_does_not_touch_subdomains():
    assert dm.matches("footprintdns.com", "footprintdns.com")
    assert not dm.matches("footprintdns.com", "a.footprintdns.com")


def test_empty_pattern_matches_nothing():
    assert not dm.matches("", "example.com")
    assert not dm.matches("*.example.com", "")


def test_matches_any_returns_the_rule_that_fired():
    rules = ["a.ru", "*.footprintdns.com"]
    assert dm.matches_any(rules, "x.footprintdns.com") == "*.footprintdns.com"
    assert dm.matches_any(rules, "b.ru") == ""


# --- нормализация правил --------------------------------------------------

def test_pattern_is_normalised_to_one_form():
    """Иначе одно и то же правило заводилось бы дважды."""
    for raw in ("*.Example.COM", "*.example.com.", ".example.com",
                "https://*.example.com/path"):
        assert dm.normalize_pattern(raw) == "*.example.com", raw


def test_exact_pattern_keeps_no_star():
    assert dm.normalize_pattern("Example.com") == "example.com"


def test_suggested_rule_covers_the_whole_service():
    assert dm.suggest_pattern("si21if1u2.afd.footprintdns.com") == \
        "*.footprintdns.com"


def test_suggested_rule_for_an_address_is_the_address():
    assert dm.suggest_pattern("10.61.50.40") == "10.61.50.40"
