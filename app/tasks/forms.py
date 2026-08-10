from flask_wtf import FlaskForm
from wtforms import (
    DateField,
    HiddenField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Length, Optional

from ..models import TASK_PRIORITIES, TASK_STATUSES


class TaskForm(FlaskForm):
    """Создание и правка задачи."""

    title = StringField(
        "Название",
        validators=[DataRequired(message="Опишите задачу одной строкой."),
                    Length(max=300)],
    )
    description = TextAreaField("Описание", validators=[Optional()])
    status = SelectField("Статус", choices=list(TASK_STATUSES))
    priority = SelectField("Приоритет", choices=list(TASK_PRIORITIES),
                           default="normal")
    assignee_id = SelectField("Исполнитель", coerce=int)
    service_id = SelectField("Сервис", validators=[Optional()])
    due_date = DateField("Срок", validators=[Optional()])
    submit = SubmitField("Сохранить")


class CommentForm(FlaskForm):
    body = TextAreaField(
        "Комментарий",
        validators=[DataRequired(message="Пустой комментарий добавлять нечего.")],
    )
    submit_comment = SubmitField("Добавить")


class QuickTaskForm(FlaskForm):
    """Постановка задачи одной строкой прямо на доске."""

    title = StringField("Задача", validators=[DataRequired(), Length(max=300)])
    assignee_id = SelectField("Исполнитель", coerce=int)
    priority = SelectField("Приоритет", choices=list(TASK_PRIORITIES),
                           default="normal")
    due_date = DateField("Срок", validators=[Optional()])
    status = HiddenField()
    submit_quick = SubmitField("Добавить")


class ChecklistForm(FlaskForm):
    """Пункты выполнения. Можно вставить сразу список — по строке на пункт."""

    text = TextAreaField(
        "Пункты выполнения",
        validators=[DataRequired(message="Введите текст пункта.")],
    )
    submit_item = SubmitField("Добавить")
