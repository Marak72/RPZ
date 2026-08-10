from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import (
    BooleanField,
    DateField,
    IntegerField,
    MultipleFileField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, NumberRange, Optional


class UploadForm(FlaskForm):
    """Загрузка одного или нескольких файлов писем за раз.

    Каждый файл сохраняется как отдельное письмо, поэтому у любого индикатора
    видно, из какого именно документа он пришёл. Реквизиты (номер, дата,
    примечание) применяются ко всем файлам пачки — так удобно грузить письмо
    вместе с приложениями.
    """

    documents = MultipleFileField(
        "Файлы писем (.docx / .odt / .pdf) — можно выбрать несколько",
        validators=[
            FileAllowed(["docx", "odt", "pdf"], "Только файлы .docx, .odt и .pdf"),
        ],
    )
    pdf = FileField(
        "PDF для просмотра (необязательно, к первому файлу)",
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
