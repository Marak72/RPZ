"""Работа с именами доменов: корневой домен и правила исключений.

Зачем корневой домен. В статистике SkyDNS сотни имён вида
``si21if1u2.afd.footprintdns.com`` — это один и тот же сервис, размазанный
по случайным поддоменам. Разбирать их поштучно бессмысленно: решение
принимается один раз про ``footprintdns.com``. Поэтому у каждого домена
считается «корень» — регистрируемое имя, — и список можно смотреть свёрнутым.

Почему список суффиксов свой. Правильный ответ даёт Public Suffix List, но
тянуть его в рантайме нельзя: приложение ставится в изолированной сети.
Поэтому здесь зашит разумный набор многосоставных суффиксов, в первую
очередь российских (``tyumen.ru``, ``msk.ru``, …) — для остальных работает
правило «последние две метки». Ошибка в редком экзотическом домене не
страшна: свёртка — это способ смотреть, а не основание для блокировки.
"""
from __future__ import annotations

import ipaddress

#: Суффиксы, под которыми регистрируют имена, — значит, корень на метку длиннее.
MULTI_LABEL_SUFFIXES = frozenset("""
ac.ru edu.ru gov.ru int.ru mil.ru test.ru net.ru org.ru com.ru pp.ru
adygeya.ru altai.ru amur.ru arkhangelsk.ru astrakhan.ru bashkiria.ru
belgorod.ru bir.ru bryansk.ru buryatia.ru cbg.ru chel.ru chelyabinsk.ru
chita.ru chukotka.ru chuvashia.ru dagestan.ru dudinka.ru e-burg.ru grozny.ru
irkutsk.ru ivanovo.ru izhevsk.ru jar.ru joshkar-ola.ru kalmykia.ru kaluga.ru
kamchatka.ru karelia.ru kazan.ru kchr.ru kemerovo.ru khabarovsk.ru
khakassia.ru khv.ru kirov.ru koenig.ru komi.ru kostroma.ru krasnoyarsk.ru
kuban.ru kurgan.ru kursk.ru lipetsk.ru magadan.ru mari.ru mari-el.ru
marine.ru mordovia.ru mosreg.ru msk.ru murmansk.ru nalchik.ru nnov.ru nov.ru
novosibirsk.ru nsk.ru omsk.ru orenburg.ru oryol.ru palana.ru penza.ru perm.ru
pskov.ru ptz.ru rnd.ru ryazan.ru sakhalin.ru samara.ru saratov.ru simbirsk.ru
smolensk.ru snz.ru spb.ru stavropol.ru stv.ru surgut.ru tambov.ru tatarstan.ru
tom.ru tomsk.ru tsaritsyn.ru tsk.ru tula.ru tuva.ru tver.ru tyumen.ru udm.ru
udmurtia.ru ulan-ude.ru vladikavkaz.ru vladimir.ru vladivostok.ru volgograd.ru
vologda.ru voronezh.ru vrn.ru vyatka.ru yakutia.ru yamal.ru yaroslavl.ru
yekaterinburg.ru yuzhno-sakhalinsk.ru zgrad.ru
com.ua net.ua org.ua edu.ua gov.ua kiev.ua kharkov.ua
com.by net.by org.by com.kz org.kz net.kz edu.kz gov.kz
co.uk org.uk ac.uk gov.uk me.uk net.uk sch.uk ltd.uk plc.uk
com.au net.au org.au edu.au gov.au id.au
co.jp ne.jp or.jp ac.jp go.jp lg.jp
co.kr or.kr ne.kr go.kr re.kr pe.kr
com.cn net.cn org.cn gov.cn edu.cn ac.cn
com.br net.br org.br gov.br edu.br
com.tr net.tr org.tr gov.tr edu.tr
co.in net.in org.in gov.in ac.in edu.in firm.in gen.in ind.in
co.za org.za net.za web.za
co.il org.il ac.il net.il gov.il
co.nz net.nz org.nz govt.nz ac.nz school.nz
co.id or.id ac.id web.id go.id
co.th in.th ac.th go.th net.th or.th
com.mx com.ar com.pl com.sg com.hk com.my com.vn com.ph com.pk com.eg
com.sa com.ng com.co com.pe com.ve com.ec com.uy com.do com.gt com.tw
com.es com.pt com.gr com.cy com.mt com.lb com.jo com.kw com.qa com.bh
net.pl org.pl edu.pl gov.pl
""".split())


def normalize(value) -> str:
    """Привести значение к домену в нижнем регистре без точки и звёздочки."""
    domain = str(value or "").strip().lower().rstrip(".")
    while domain.startswith("*."):
        domain = domain[2:]
    return domain.lstrip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def registrable(value) -> str:
    """Корневой (регистрируемый) домен: ``a.b.example.co.uk`` → ``example.co.uk``.

    Для адресов и одно-двухсоставных имён возвращает их же — сворачивать там
    нечего.
    """
    domain = normalize(value)
    if not domain or is_ip(domain):
        return domain

    labels = domain.split(".")
    if len(labels) <= 2:
        return domain

    suffix = ".".join(labels[-2:])
    if suffix in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def subdomain_part(value) -> str:
    """Часть имени слева от корня: ``si21if1u2.afd`` для footprintdns.com."""
    domain = normalize(value)
    root = registrable(domain)
    if domain == root:
        return ""
    return domain[: -(len(root) + 1)]


def matches(pattern: str, domain: str) -> bool:
    """Подходит ли домен под правило исключения.

    Понимаются два вида правил:

    * ``example.com``   — только этот домен;
    * ``*.example.com`` — этот домен и все его поддомены. Апекс включён
      намеренно: оператор, исключающий ``*.footprintdns.com``, имеет в виду
      «этот сервис целиком», а не «всё кроме самого короткого имени».
    """
    domain = normalize(domain)
    raw = str(pattern or "").strip().lower().rstrip(".")
    if not raw or not domain:
        return False

    if raw.startswith("*."):
        base = normalize(raw)
        return domain == base or domain.endswith("." + base)
    return domain == normalize(raw)


def matches_any(patterns, domain: str) -> str:
    """Первое подошедшее правило (или пустая строка)."""
    for pattern in patterns:
        if matches(pattern, domain):
            return pattern
    return ""


def suggest_pattern(domain: str) -> str:
    """Правило, которое стоит предложить оператору для этого домена.

    Для поддомена — весь корень целиком: ровно этого и хотят, увидев
    десяток случайных имён одного сервиса.
    """
    domain = normalize(domain)
    root = registrable(domain)
    if not root or is_ip(domain):
        return domain
    return f"*.{root}"
