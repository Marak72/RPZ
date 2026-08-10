from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    widgets,
)
from wtforms.validators import DataRequired, EqualTo, Length, Optional, Regexp

from ..models import ROLES

# Простая проверка адреса: полноценный валидатор WTForms тянет отдельный пакет,
# а приложение должно ставиться в изолированной сети без доступа к PyPI.
EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class ServicePicker(SelectMultipleField):
    """Набор галочек вместо списка с множественным выбором."""

    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class UserForm(FlaskForm):
    """Создание и правка учётной записи сотрудника."""

    username = StringField(
        "Логин",
        validators=[DataRequired(message="Укажите логин."), Length(max=80)],
    )
    full_name = StringField("ФИО", validators=[Optional(), Length(max=200)])
    position = StringField("Должность", validators=[Optional(), Length(max=200)])
    email = StringField(
        "Электронная почта",
        validators=[Optional(), Regexp(EMAIL_RE, message="Похоже на неверный адрес."),
                    Length(max=200)],
    )
    role = SelectField("Роль", choices=list(ROLES))
    services = ServicePicker("Доступные сервисы", coerce=str)
    is_enabled = BooleanField("Учётная запись активна", default=True)
    password = PasswordField(
        "Пароль", validators=[Optional(), Length(min=8, message="Не короче 8 символов.")]
    )
    password2 = PasswordField(
        "Пароль ещё раз",
        validators=[Optional(), EqualTo("password", message="Пароли не совпадают.")],
    )
    submit = SubmitField("Сохранить")


class PasswordForm(FlaskForm):
    """Смена собственного пароля."""

    current = PasswordField("Текущий пароль", validators=[DataRequired()])
    password = PasswordField(
        "Новый пароль",
        validators=[DataRequired(), Length(min=8, message="Не короче 8 символов.")],
    )
    password2 = PasswordField(
        "Новый пароль ещё раз",
        validators=[DataRequired(), EqualTo("password", message="Пароли не совпадают.")],
    )
    submit_password = SubmitField("Сменить пароль")


class ProfileForm(FlaskForm):
    """Собственные реквизиты сотрудника."""

    full_name = StringField("ФИО", validators=[Optional(), Length(max=200)])
    position = StringField("Должность", validators=[Optional(), Length(max=200)])
    email = StringField(
        "Электронная почта",
        validators=[Optional(), Regexp(EMAIL_RE, message="Похоже на неверный адрес."),
                    Length(max=200)],
    )
    submit_profile = SubmitField("Сохранить")
