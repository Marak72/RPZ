"""Ядро портала — то, что общее для всех сервисов и никогда не дублируется.

    extensions.py     db / migrate / csrf / login_manager
    models.py         User / UserService / AppSetting / BackgroundJob / VtReport
    crypto.py         шифрование секретов (Fernet)
    settings_store.py настройки приложения, секреты — зашифрованно
    web_utils.py      общие помощники страниц: роли, доступ к сервисам, CSV
    background.py     движок фоновых заданий (страницы заданий — в app/jobs)
    vt_client.py      клиент VirusTotal
    vt_store.py       кэш вердиктов VirusTotal, общий для сервисов

Ядро не знает о конкретных сервисах и никогда их не импортирует — зависимость
всегда направлена от сервиса к ядру.
"""
