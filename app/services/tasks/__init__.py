"""Сервис «Задачи отдела» — доска задач, карточки, комментарии, загрузка.

Всё, что относится к сервису, лежит в этой папке::

    routes.py     доска, карточка задачи, мои задачи, загрузка отдела
    forms.py      формы задачи и пунктов выполнения
    models.py     Task / TaskChecklistItem / TaskComment / TaskEvent
    templates/tasks/  страницы сервиса и его боковая навигация
"""
from . import models  # noqa: F401 — модели должны быть видны SQLAlchemy
from .routes import tasks_bp

__all__ = ["tasks_bp", "models"]
