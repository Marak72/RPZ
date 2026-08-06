from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    StringField,
    SubmitField,
)
from wtforms.validators import DataRequired, NumberRange, Optional


class UploadForm(FlaskForm):
    document = FileField(
        "Письмо ФСТЭК (.docx / .odt)",
        validators=[
            FileRequired(message="Выберите файл."),
            FileAllowed(["docx", "odt"], "Только файлы .docx и .odt"),
        ],
    )
    notes = StringField("Примечание (номер/дата письма)", validators=[Optional()])
    submit = SubmitField("Загрузить и распознать")


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
    use_sudo = BooleanField("Выполнять команды через sudo -n", default=False)
    validate_zone = BooleanField(
        "Проверять зону через named-checkzone перед записью", default=True
    )
    reload_zone = BooleanField("Перезагружать зону (rndc reload)", default=True)
    is_active = BooleanField("Активная учётная запись", default=True)
    submit = SubmitField("Сохранить")
    test = SubmitField("Проверить подключение")
