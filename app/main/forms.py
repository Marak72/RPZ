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


class UploadForm(FlaskForm):
    document = FileField(
        "Файл письма (.docx / .odt / .pdf)",
        validators=[
            FileRequired(message="Выберите файл."),
            FileAllowed(["docx", "odt", "pdf"], "Только файлы .docx, .odt и .pdf"),
        ],
    )
    pdf = FileField(
        "PDF письма для просмотра (необязательно)",
        validators=[Optional(), FileAllowed(["pdf"], "Только файл .pdf")],
    )
    letter_number = StringField("Номер письма", validators=[Optional()])
    letter_date = DateField("Дата письма", validators=[Optional()])
    notes = StringField("Примечание", validators=[Optional()])
    submit = SubmitField("Загрузить и распознать")


class ManualAddForm(FlaskForm):
    """Ручное добавление доменов или IP-адресов (по одному в строке)."""

    values = TextAreaField(
        "Домены или IP-адреса",
        validators=[DataRequired(message="Введите хотя бы одно значение.")],
    )
    notes = StringField("Примечание", validators=[Optional()])
    submit = SubmitField("Добавить")


class NotesForm(FlaskForm):
    notes = TextAreaField("Заметка", validators=[Optional()])
    submit = SubmitField("Сохранить заметку")


class SshServerForm(FlaskForm):
    name = StringField("Название", validators=[DataRequired()])
    host = StringField("Хост / IP", validators=[DataRequired()])
    port = IntegerField(
        "Порт", validators=[DataRequired(), NumberRange(min=1, max=65535)], default=22
    )
    username = StringField("Логин SSH", validators=[DataRequired()])
    password = PasswordField(
        "Пароль SSH (оставьте пустым, чтобы не менять)", validators=[Optional()]
    )
    zone_file_path = StringField(
        "Путь к файлу RPZ-зоны",
        validators=[DataRequired()],
        default="/var/named/master/rpz.block.db",
    )
    zone_name = StringField(
        "Имя зоны (для named-checkzone и rndc reload)",
        validators=[DataRequired()],
        default="rpz.block",
    )
    use_sudo = BooleanField(
        "Файловые операции через sudo -n (если нет прав на файл зоны)", default=False
    )
    sudo_rndc = BooleanField(
        "Только rndc reload через sudo -n (узкое правило в sudoers)", default=False
    )
    validate_zone = BooleanField(
        "Проверять зону через named-checkzone перед записью", default=True
    )
    reload_zone = BooleanField("Перезагружать зону (rndc reload)", default=True)
    is_active = BooleanField("Активная учётная запись", default=True)
    submit = SubmitField("Сохранить")
    test = SubmitField("Проверить подключение")


class AppSettingsForm(FlaskForm):
    """Общие настройки: ключ VirusTotal и защищённые домены."""

    vt_api_key = PasswordField(
        "Ключ API VirusTotal (оставьте пустым, чтобы не менять)",
        validators=[Optional()],
    )
    protected_domains = TextAreaField(
        "Защищённые домены (по одному в строке)", validators=[Optional()]
    )
    submit_app = SubmitField("Сохранить")


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
    submit_siem = SubmitField("Сохранить")
    test_siem = SubmitField("Проверить подключение")


class SkydnsSettingsForm(FlaskForm):
    """Подключение к API SkyDNS и разбор его выгрузок."""

    base_url = StringField("Адрес API SkyDNS", validators=[Optional()])
    stats_path = StringField("Путь метода статистики", validators=[Optional()])
    login = StringField("Логин", validators=[Optional()])
    password = PasswordField(
        "Пароль (оставьте пустым, чтобы не менять)", validators=[Optional()]
    )
    token = PasswordField(
        "Токен API (оставьте пустым, чтобы не менять)", validators=[Optional()]
    )
    profile = StringField("Профиль / ident", validators=[Optional()])
    days = IntegerField(
        "Глубина выборки по умолчанию, дней",
        validators=[Optional(), NumberRange(min=1, max=365)],
    )
    verify_ssl = BooleanField("Проверять сертификат SkyDNS", default=True)
    categories = TextAreaField(
        "Категории безопасности (по одной в строке)", validators=[Optional()]
    )
    field_map = TextAreaField(
        "Сопоставление полей ответа (JSON, необязательно)", validators=[Optional()]
    )
    submit_skydns = SubmitField("Сохранить")
