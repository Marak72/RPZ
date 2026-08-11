from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import (
    BooleanField,
    DateField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, NumberRange, Optional


class SyncForm(FlaskForm):
    """Выгрузка статистики из API SkyDNS за период."""

    start = DateField("Начало периода", validators=[Optional()])
    end = DateField("Конец периода", validators=[Optional()])
    submit_sync = SubmitField("Забрать из SkyDNS")


class ImportForm(FlaskForm):
    """Импорт выгрузки статистики из личного кабинета SkyDNS."""

    report = FileField(
        "Файл статистики (.csv)",
        validators=[
            FileRequired(message="Выберите файл."),
            FileAllowed(["csv", "txt"], "Только файлы .csv"),
        ],
    )
    submit_import = SubmitField("Загрузить файл")


class ManualThreatForm(FlaskForm):
    """Ручное добавление домена в разбор (по одному в строке)."""

    values = TextAreaField(
        "Домены",
        validators=[DataRequired(message="Введите хотя бы один домен.")],
    )
    category = StringField("Категория", validators=[Optional()])
    submit_manual = SubmitField("Добавить")


class ThreatNotesForm(FlaskForm):
    status = SelectField("Статус разбора", validators=[Optional()])
    notes = TextAreaField("Заметка", validators=[Optional()])
    submit_notes = SubmitField("Сохранить")


class SiemSettingsForm(FlaskForm):
    """Подключение к MaxPatrol SIEM для поиска конечных хостов."""

    base_url = StringField("Адрес SIEM", validators=[Optional()])
    auth_mode = SelectField(
        "Способ аутентификации",
        choices=[
            ("session", "Сессия через форму /ui/login (порт 3334)"),
            ("token", "Токен OAuth2 /connect/token (порт 3334)"),
        ],
        default="session",
    )
    auth_type = SelectField(
        "Тип учётной записи",
        choices=[("local", "Локальная"), ("ldap", "LDAP / доменная")],
        default="local",
    )
    username = StringField("Логин", validators=[Optional()])
    password = PasswordField(
        "Пароль (оставьте пустым, чтобы не менять)", validators=[Optional()]
    )
    client_id = StringField("client_id (для режима токена)", validators=[Optional()])
    client_secret = PasswordField(
        "client_secret (оставьте пустым, чтобы не менять)", validators=[Optional()]
    )
    verify_ssl = BooleanField("Проверять сертификат SIEM", default=False)
    filter_template = StringField("Шаблон фильтра", validators=[Optional()])
    group_field = StringField("Поле группировки", validators=[Optional()])
    window_hours = IntegerField(
        "Окно поиска, часов",
        validators=[Optional(), NumberRange(min=1, max=24 * 365)],
    )
    limit = IntegerField(
        "Максимум строк в ответе",
        validators=[Optional(), NumberRange(min=10, max=10000)],
    )
    timeout = IntegerField(
        "Таймаут запроса, секунд",
        validators=[Optional(), NumberRange(min=10, max=600)],
    )
    submit_siem = SubmitField("Сохранить")
    test_siem = SubmitField("Проверить подключение")


class SiemProbeForm(FlaskForm):
    """Разовый запрос в SIEM с показом сырого ответа.

    Нужна, когда поиск возвращает ноль хостов: по журналу не отличить
    «событий не нашлось» от «значение группировки лежит в другом поле».
    """

    domain = StringField("Домен", validators=[DataRequired()])
    submit_probe = SubmitField("Выполнить запрос")


class SkydnsSettingsForm(FlaskForm):
    """Подключение к Proxy Stat API SkyDNS."""

    base_url = StringField("Адрес SkyDNS", validators=[Optional()])
    user_id = StringField("ID пользователя (user_id в адресе API)",
                          validators=[Optional()])
    token = PasswordField(
        "Токен API (оставьте пустым, чтобы не менять)", validators=[Optional()]
    )
    profile_ids = StringField("Профили (profile_ids через запятую)",
                              validators=[Optional()])
    timezone = StringField("Временная зона отчётов", validators=[Optional()])
    days = IntegerField(
        "Глубина выборки по умолчанию, дней",
        validators=[Optional(), NumberRange(min=1, max=365)],
    )
    limit = IntegerField(
        "Максимум доменов в отчёте",
        validators=[Optional(), NumberRange(min=10, max=100000)],
    )
    detail_limit = IntegerField(
        "Максимум строк детализации",
        validators=[Optional(), NumberRange(min=100, max=200000)],
    )
    report_timeout = IntegerField(
        "Ждать готовности отчёта, секунд",
        validators=[Optional(), NumberRange(min=30, max=3600)],
    )
    auto_devices = BooleanField(
        "Сразу запрашивать устройства по новым доменам", default=True
    )
    verify_ssl = BooleanField("Проверять сертификат SkyDNS", default=True)
    submit_skydns = SubmitField("Сохранить")
    test_skydns = SubmitField("Проверить подключение")
