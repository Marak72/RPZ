# Развёртывание на сервере (подпуть /soc)

Портал запускается как отдельный сервис (gunicorn) и отдаётся через
существующий веб-сервер на подпути:

    https://soc-dashboards.72to.ru/soc/           — главная портала
    https://soc-dashboards.72to.ru/soc/fstec/     — сервис «РПЗ ФСТЭК»
    https://soc-dashboards.72to.ru/soc/skydns/    — сервис «Угрозы SkyDNS»

Сайт в корне домена и соседние приложения (`/vault/` и т. п.) не затрагиваются —
добавляется только один новый блок.

```
Браузер ──HTTPS──> httpd/nginx (soc-dashboards.72to.ru)
                     ├── /          → существующий сайт (как было)
                     ├── /vault/    → Vaultwarden (как было)
                     └── /soc/      → proxy → gunicorn 127.0.0.1:8000 → Flask
                                        ├── /           главная портала
                                        ├── /fstec/     РПЗ ФСТЭК
                                        └── /skydns/    Угрозы SkyDNS
```

## 1. Подготовка кода на сервере

```bash
sudo mkdir -p /opt/fstec-rpz
sudo chown "$USER" /opt/fstec-rpz
git clone <URL-репозитория> /opt/fstec-rpz
cd /opt/fstec-rpz
git checkout claude/bold-archimedes-yxxzjk

python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

## 2. Файл окружения `.env`

```bash
cp deploy/env.example /opt/fstec-rpz/.env
# Сгенерировать и вписать секреты:
python -c "import secrets; print('SECRET_KEY='+secrets.token_hex(32))"
python -c "from cryptography.fernet import Fernet; print('RPZ_FERNET_KEY='+Fernet.generate_key().decode())"
nano /opt/fstec-rpz/.env          # вставить значения, оставить BEHIND_PROXY=1
chmod 600 /opt/fstec-rpz/.env
```

> ⚠️ Сохраните `RPZ_FERNET_KEY` отдельно: при его потере/смене сохранённые
> пароли SSH расшифровать будет нельзя — придётся ввести УЗ заново.

## 3. Инициализация БД и пользователей

```bash
cd /opt/fstec-rpz && . venv/bin/activate
set -a && . ./.env && set +a          # подгрузить переменные окружения
export FLASK_APP=run.py
flask db upgrade
flask create-user admin --role operator
flask create-user boss  --role manager
```

SQLite-файл создаётся в `/opt/fstec-rpz/instance/rpz.db`. Каталог `instance/`
должен быть доступен на запись пользователю сервиса (см. ниже).

## 4. Сервис gunicorn (systemd)

```bash
# 1. Пользователь службы. Имена различаются между дистрибутивами
#    (Debian/Ubuntu: www-data, ALT: apache2, RHEL: apache), поэтому надёжнее
#    завести свою учётную запись — приложение слушает только 127.0.0.1 и
#    совпадать с пользователем веб-сервера ему не нужно.
sudo useradd -r -s /sbin/nologin socportal

sudo cp deploy/soc-portal.service /etc/systemd/system/soc-portal.service
# 2. ОБЯЗАТЕЛЬНО: вписать этого пользователя в юнит (в файле стоит заглушка).
sudo sed -i 's/^User=.*/User=socportal/; s/^Group=.*/Group=socportal/' \
    /etc/systemd/system/soc-portal.service

# 3. Дать ему доступ к данным приложения.
sudo chown -R socportal:socportal /opt/fstec-rpz/instance

sudo systemctl daemon-reload
sudo systemctl enable --now soc-portal
sudo systemctl status soc-portal     # должно быть active (running)
curl -s http://127.0.0.1:8000/login | head   # проверка, что gunicorn отвечает
```

> Если служба падает с `status=217/USER` — указанного пользователя в системе
> нет. Проверить: `id <имя>`. Это самая частая ошибка на этом шаге.

## 5. Конфигурация веб-сервера

Нужен один блок в существующем HTTPS-хосте. Корневой сайт и соседние приложения
не затрагиваются.

Определить, какой веб-сервер работает: `sudo ss -ltnp | grep ':443'`.

### Apache (httpd / httpd2)

Готовый фрагмент — `deploy/apache-soc.conf`. Вставьте его внутрь существующего
`<VirtualHost *:443>`:

```apache
    # /soc без слэша -> /soc/
    RedirectMatch ^/soc$ /soc/

    <Location /soc/>
        Require all granted
        ProxyPass        http://127.0.0.1:8000/ timeout=180
        ProxyPassReverse http://127.0.0.1:8000/
        RequestHeader set X-Real-IP          %{REMOTE_ADDR}s
        RequestHeader set X-Forwarded-Proto  "https"
        RequestHeader set X-Forwarded-Port   "443"
        RequestHeader set X-Forwarded-Prefix "/soc"
    </Location>
```

Нужны модули `mod_proxy`, `mod_proxy_http`, `mod_headers`, `mod_rewrite`.
Применить:

```bash
sudo apachectl configtest && sudo systemctl reload httpd2   # или httpd / apache2
```

### nginx

Готовый фрагмент — `deploy/nginx-soc.conf`. Вставьте внутрь блока
`server { listen 443 ssl; ... }`:

```nginx
    location = /soc { return 301 /soc/; }
    location /soc/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /soc;
        client_max_body_size 10m;
        proxy_read_timeout 180s;
        proxy_send_timeout 180s;
    }
```

Применить:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Откройте `https://soc-dashboards.72to.ru/soc/` — должна открыться страница входа,
а после входа — главная портала со списком сервисов.

## 6. Обновление приложения

```bash
cd /opt/fstec-rpz && git pull && . venv/bin/activate
pip install -r requirements.txt
# Резервная копия базы — миграции лучше катать с возможностью откатиться.
cp instance/rpz.db "instance/rpz.db.$(date +%F-%H%M).bak"
set -a && . ./.env && set +a && export FLASK_APP=run.py && flask db upgrade
sudo systemctl restart soc-portal
```

Если обновление приносит новые таймауты или параметры запуска (как выпуск с
сервисом «Угрозы SkyDNS»), обновите и конфиги:

```bash
sudo cp deploy/soc-portal.service /etc/systemd/system/soc-portal.service
sudo systemctl daemon-reload && sudo systemctl restart soc-portal
# и перенесите новые директивы таймаута в конфиг веб-сервера, затем:
sudo nginx -t && sudo systemctl reload nginx      # или: apachectl configtest && systemctl reload httpd
```

Откат последней миграции, если что-то пошло не так:

```bash
set -a && . ./.env && set +a && export FLASK_APP=run.py && flask db downgrade
sudo systemctl restart soc-portal
```

## 7. Переезд с прежней схемы (/fstec, служба fstec)

Если сервис уже стоял как «РПЗ ФСТЭК» на `/fstec/`, переход на портал делается так.
База, файлы писем и `.env` не трогаются — каталог остаётся прежним.

```bash
cd /opt/fstec-rpz
git fetch origin claude/bold-archimedes-yxxzjk
git checkout claude/bold-archimedes-yxxzjk
. venv/bin/activate

cp instance/rpz.db "instance/rpz.db.$(date +%F-%H%M).bak"
set -a && . ./.env && set +a && export FLASK_APP=run.py
flask db upgrade

# Старая служба заменяется новой (имя больше не отражало содержимое).
# СНАЧАЛА запоминаем её пользователя: он владеет базой и файлами писем,
# в новом юните на его месте стоит заглушка.
SVC_USER=$(awk -F= '/^User=/{print $2}' /etc/systemd/system/fstec.service)
SVC_GROUP=$(awk -F= '/^Group=/{print $2}' /etc/systemd/system/fstec.service)
echo "было: User=$SVC_USER Group=$SVC_GROUP"     # не должно быть пусто

sudo systemctl disable --now fstec
sudo cp deploy/soc-portal.service /etc/systemd/system/soc-portal.service
sudo sed -i "s/^User=.*/User=$SVC_USER/; s/^Group=.*/Group=$SVC_GROUP/" \
    /etc/systemd/system/soc-portal.service

sudo systemctl daemon-reload
sudo systemctl enable --now soc-portal
sudo systemctl status soc-portal

# Убедились, что служба поднялась, — только теперь убираем старый юнит.
sudo rm -f /etc/systemd/system/fstec.service && sudo systemctl daemon-reload
```

> Если старый юнит уже удалён и `User` подсмотреть негде, возьмите владельца
> данных приложения: `stat -c '%U:%G' /opt/fstec-rpz/instance`.

Затем в конфиге веб-сервера замените блок `/fstec/` на блок `/soc/` из раздела 5
(меняются сам путь, `X-Forwarded-Prefix` и добавляется таймаут) и перезагрузите
веб-сервер.

Новый адрес: `https://soc-dashboards.72to.ru/soc/`. Старый `/fstec/` перестаёт
работать — разошлите новую ссылку коллегам.

## Примечания

- **Почему подпуть работает корректно:** при `BEHIND_PROXY=1` приложение через
  `ProxyFix` читает заголовки `X-Forwarded-Proto/Host/Prefix`, поэтому `url_for`,
  редиректы и cookie сессии формируются с префиксом `/soc` и схемой `https`.
- **Как определить веб-сервер**, если не уверены: `sudo ss -ltnp | grep ':443'`
  покажет процесс (`nginx`, `httpd`, `httpd2` или `apache2`). Найти, где описан
  подпуть: `sudo grep -rn "/soc/" /etc/nginx/ /etc/httpd*/ /etc/apache2/`.
- **`status=217/USER` при старте службы:** пользователя из `User=` нет в
  системе. Имена различаются между дистрибутивами (`www-data`, `apache2`,
  `apache`), поэтому в юните из репозитория стоит заглушка, которую нужно
  заменить. Владельца данных подскажет `stat -c '%U:%G' /opt/fstec-rpz/instance`.
- **Доступ к DNS-серверу:** SSH-подключение к BIND настраивается уже внутри
  приложения (раздел «Настройки»), на этапе развёртывания ничего не требуется.
- **Сервис «Угрозы SkyDNS»** появляется вкладкой в боковой панели после
  `flask db upgrade` (миграция `a1c7f3d90e42` создаёт таблицы `threat_domains`,
  `threat_hosts`, `siem_query_logs`, `skydns_sync_logs`). Подключения к SkyDNS и
  MaxPatrol SIEM задаются в разделе «Настройки», на этапе развёртывания ничего
  не требуется.
- **Сетевой доступ для сервиса SkyDNS:** с сервера приложения нужен HTTPS до
  MaxPatrol SIEM (веб-порт и порт компонента Core `3334`) и до API SkyDNS.
  Без них сервис остаётся рабочим в режиме импорта CSV.
- **Таймауты при поиске в SIEM:** запрос выполняется синхронно, пакетная
  проверка ограничена 25 доменами. Если SIEM отвечает медленно, поднимите
  `--timeout` у gunicorn в `deploy/soc-portal.service` и
  `proxy_read_timeout` в конфиге веб-сервера.
