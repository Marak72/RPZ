from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import DateField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Optional


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
