"""Точка входа для production-сервера WSGI (gunicorn).

Запуск:
    gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:application
"""
from app import create_app

application = create_app()
