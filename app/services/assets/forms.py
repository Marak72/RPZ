"""Формы сервиса «Узлы сети»."""
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, NumberRange, Optional


class SearchForm(FlaskForm):
    """Единая строка поиска: адрес, имя, MAC или кусок описания."""

    q = StringField("Что ищем", validators=[Optional()])
    submit_search = SubmitField("Найти")


class AdSettingsForm(FlaskForm):
    """Подключение к Active Directory."""

    host = StringField("Контроллер домена", validators=[Optional()])
    port = IntegerField("Порт", validators=[Optional(),
                                            NumberRange(min=1, max=65535)])
    use_ssl = BooleanField("Шифровать соединение (LDAPS)")
    domain = StringField("Домен", validators=[Optional()])
    base_dn = StringField("База поиска (Base DN)", validators=[Optional()])
    username = StringField("Учётная запись", validators=[Optional()])
    password = PasswordField("Пароль", validators=[Optional()])
    timeout = IntegerField("Таймаут, секунд",
                           validators=[Optional(), NumberRange(min=5, max=600)])
    submit_ad = SubmitField("Сохранить")
    test_ad = SubmitField("Проверить связь")


class DhcpSettingsForm(FlaskForm):
    """Подключение к DHCP через WinRM."""

    host = StringField("Сервер для выполнения команд", validators=[Optional()])
    port = IntegerField("Порт WinRM", validators=[Optional(),
                                                  NumberRange(min=1, max=65535)])
    use_ssl = BooleanField("Шифровать соединение (HTTPS)")
    username = StringField("Учётная запись", validators=[Optional()])
    password = PasswordField("Пароль", validators=[Optional()])
    timeout = IntegerField("Таймаут, секунд",
                           validators=[Optional(), NumberRange(min=10, max=1800)])
    discover = BooleanField("Искать все серверы DHCP в домене")
    servers = TextAreaField("Серверы DHCP", validators=[Optional()])
    submit_dhcp = SubmitField("Сохранить")
    test_dhcp = SubmitField("Проверить связь")


class SyncForm(FlaskForm):
    """Запуск выгрузки."""

    submit_dhcp = SubmitField("Выгрузить аренды DHCP")
    submit_ad = SubmitField("Выгрузить компьютеры AD")


class HostNotesForm(FlaskForm):
    notes = TextAreaField("Заметка", validators=[Optional()])
    submit_notes = SubmitField("Сохранить заметку")


class ManualHostForm(FlaskForm):
    """Ручное добавление адреса — для узлов вне DHCP и AD."""

    ip = StringField("Адрес", validators=[DataRequired(message="Введите адрес.")])
    hostname = StringField("Имя узла", validators=[Optional()])
    notes = TextAreaField("Чем является", validators=[Optional()])
    submit_manual = SubmitField("Добавить")
