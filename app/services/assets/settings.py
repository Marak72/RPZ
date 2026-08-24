"""Настройки сервиса «Узлы сети»: подключения к Active Directory и DHCP.

Значения лежат в общей таблице ``app_settings``; здесь — только то, что знает
этот сервис: имена ключей, умолчания и сборка объектов подключения.

Пароль учётной записи хранится зашифрованным (Fernet, тот же ключ, что у
паролей SSH и SIEM) и в интерфейсе никогда не показывается — форма умеет
только перезаписать его новым значением.
"""
from __future__ import annotations

from ...core.settings_store import (  # noqa: F401 — переэкспорт для сервиса
    get_bool,
    get_int,
    get_setting,
    set_setting,
)

# --- Active Directory -----------------------------------------------------
KEY_AD_HOST = "assets_ad_host"            # контроллер домена
KEY_AD_PORT = "assets_ad_port"
KEY_AD_SSL = "assets_ad_ssl"
KEY_AD_BASE_DN = "assets_ad_base_dn"
KEY_AD_DOMAIN = "assets_ad_domain"        # adm72.local — для подсказок и base_dn
KEY_AD_USER = "assets_ad_user"            # ДОМЕН\пользователь
KEY_AD_PASSWORD = "assets_ad_password"    # секрет
KEY_AD_TIMEOUT = "assets_ad_timeout"

# --- DHCP (через WinRM) ---------------------------------------------------
KEY_DHCP_HOST = "assets_dhcp_host"        # где выполняются команды PowerShell
KEY_DHCP_PORT = "assets_dhcp_port"
KEY_DHCP_SSL = "assets_dhcp_ssl"
KEY_DHCP_TIMEOUT = "assets_dhcp_timeout"
# Отдельная учётная запись для DHCP нужна редко: обычно та же, что для AD.
KEY_DHCP_USER = "assets_dhcp_user"
KEY_DHCP_PASSWORD = "assets_dhcp_password"  # секрет
# Ограничить выгрузку перечисленными серверами (по одному в строке).
# Пусто — см. KEY_DHCP_DISCOVER.
KEY_DHCP_SERVERS = "assets_dhcp_servers"
# Искать все серверы DHCP в домене (Get-DhcpServerInDC) или ограничиться тем,
# к которому подключаемся. По умолчанию выключено, и вот почему: в домене
# зарегистрирован 61 сервер, но дотянуться контроллер смог ровно до одного —
# остальные закрыты межсетевыми экранами между площадками. Веер по всем давал
# 60 отказов «Failed to get version», раздутый журнал и потерянное время при
# ровно том же итоге.
KEY_DHCP_DISCOVER = "assets_dhcp_discover"

#: Глобальный каталог, а не обычный LDAP: домен разнесён по области, и объект
#: машины лежит в своём сайте. Порт 389 отвечает только за свой раздел и на
#: чужую площадку ответит «не найдено».
DEFAULT_AD_PORT = 3268
DEFAULT_AD_SSL_PORT = 3269
DEFAULT_AD_TIMEOUT = 20
DEFAULT_DHCP_PORT = 5985
DEFAULT_DHCP_TIMEOUT = 120


def load_ldap_config():
    """Собрать параметры подключения к каталогу из настроек."""
    from .lib.ldap_client import LdapConfig, base_dn_from_domain

    domain = get_setting(KEY_AD_DOMAIN, "")
    base_dn = get_setting(KEY_AD_BASE_DN, "") or base_dn_from_domain(domain)
    use_ssl = get_bool(KEY_AD_SSL, False)
    return LdapConfig(
        host=get_setting(KEY_AD_HOST, ""),
        port=get_int(KEY_AD_PORT,
                     DEFAULT_AD_SSL_PORT if use_ssl else DEFAULT_AD_PORT),
        use_ssl=use_ssl,
        base_dn=base_dn,
        username=get_setting(KEY_AD_USER, ""),
        password=get_setting(KEY_AD_PASSWORD, ""),
        timeout=get_int(KEY_AD_TIMEOUT, DEFAULT_AD_TIMEOUT),
    )


def load_dhcp_config():
    """Собрать параметры подключения к DHCP.

    Учётная запись по умолчанию берётся та же, что для каталога: заводить две
    одинаковые пары «логин — пароль» ради одной и той же доменной учётки —
    лишний повод ошибиться при смене пароля.
    """
    from .lib.dhcp_client import DhcpConfig

    return DhcpConfig(
        host=get_setting(KEY_DHCP_HOST, "") or get_setting(KEY_AD_HOST, ""),
        port=get_int(KEY_DHCP_PORT, DEFAULT_DHCP_PORT),
        use_ssl=get_bool(KEY_DHCP_SSL, False),
        username=get_setting(KEY_DHCP_USER, "") or get_setting(KEY_AD_USER, ""),
        password=get_setting(KEY_DHCP_PASSWORD, "")
                 or get_setting(KEY_AD_PASSWORD, ""),
        timeout=get_int(KEY_DHCP_TIMEOUT, DEFAULT_DHCP_TIMEOUT),
    )


def allowed_servers() -> list[str]:
    """Явно заданный список DHCP-серверов, если оператор его сузил."""
    raw = get_setting(KEY_DHCP_SERVERS, "")
    return [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def discover_servers() -> bool:
    """Спрашивать ли у домена список всех серверов DHCP."""
    return get_bool(KEY_DHCP_DISCOVER, False)


def target_servers() -> list[str]:
    """Какие серверы DHCP опрашивать, если список не задан вручную.

    Пустой ответ означает «спросить у домена» — решение принимает вызывающий,
    потому что для этого нужно живое соединение.
    """
    explicit = allowed_servers()
    if explicit:
        return explicit
    if discover_servers():
        return []
    host = get_setting(KEY_DHCP_HOST, "") or get_setting(KEY_AD_HOST, "")
    return [host] if host else []
