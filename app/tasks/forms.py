from flask_wtf import FlaskForm
from wtforms import (
    DateField,
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
