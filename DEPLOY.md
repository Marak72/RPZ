# Развёртывание на сервере (nginx, подпуть /fstec)

Приложение запускается как отдельный сервис (gunicorn) и отдаётся через
существующий nginx на подпути:

    https://soc-dashboards.72to.ru/fstec/

Сайт в корне домена не затрагивается — добавляется только новый `location`.

```
Браузер ──HTTPS──> nginx (soc-dashboards.72to.ru)
                     ├── /            → существующий сайт (как было)
                     └── /fstec/      → proxy_pass → gunicorn 127.0.0.1:8000 → Flask
```

## 1. Подготовка кода на сервере

```bash
sudo mkdir -p /opt/fstec-rpz
sudo chown "$USER" /opt/fstec-rpz
git clone <URL-репозитория> /opt/fstec-rpz
cd /opt/fstec-rpz
git checkout claude/adoring-newton-t05n51

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
sudo cp deploy/fstec.service /etc/systemd/system/fstec.service
# При необходимости поправьте User/Group и WorkingDirectory в файле.
# Дать пользователю сервиса доступ к каталогу:
sudo chown -R www-data:www-data /opt/fstec-rpz/instance

sudo systemctl daemon-reload
sudo systemctl enable --now fstec
sudo systemctl status fstec          # должно быть active (running)
curl -s http://127.0.0.1:8000/login | head   # проверка, что gunicorn отвечает
```

## 5. Конфигурация nginx

Откройте конфиг существующего сайта (обычно
`/etc/nginx/sites-available/soc-dashboards.72to.ru` или файл в `conf.d/`),
найдите блок `server { ... }` для HTTPS (порт 443) и вставьте внутрь
содержимое `deploy/nginx-fstec.conf`:

```nginx
server {
    listen 443 ssl;
    server_name soc-dashboards.72to.ru;
    # ... существующие ssl_certificate и корневой сайт ...

    # >>> добавить блоки из deploy/nginx-fstec.conf <<<
    location = /fstec { return 301 /fstec/; }
    location /fstec/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /fstec;
        client_max_body_size 10m;
    }
}
```

Применить:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Откройте `https://soc-dashboards.72to.ru/fstec/` — должна открыться страница входа.

## 6. Обновление приложения

```bash
cd /opt/fstec-rpz && git pull && . venv/bin/activate
pip install -r requirements.txt
set -a && . ./.env && set +a && export FLASK_APP=run.py && flask db upgrade
sudo systemctl restart fstec
```

## Примечания

- **Почему подпуть работает корректно:** при `BEHIND_PROXY=1` приложение через
  `ProxyFix` читает заголовки `X-Forwarded-Proto/Host/Prefix`, поэтому `url_for`,
  редиректы и cookie сессии формируются с префиксом `/fstec` и схемой `https`.
- **Как определить веб-сервер**, если не уверены: `sudo ss -ltnp | grep ':443'`
  или `systemctl status nginx`.
- **Доступ к DNS-серверу:** SSH-подключение к BIND настраивается уже внутри
  приложения (раздел «Настройки»), на этапе развёртывания ничего не требуется.
