from datetime import datetime

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import SQLAlchemyError

from ..core.extensions import db
from ..core.models import User
from .forms import LoginForm

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("hub.index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if not user.is_enabled:
                flash(
                    "Учётная запись отключена. Обратитесь к администратору портала.",
                    "danger",
                )
                return render_template("login.html", form=form)
            login_user(user)
            # Отметка о входе — сведение для журнала, а не часть входа.
            # Пользователь уже опознан, сессия уже выдана; если база в этот
            # момент занята (идёт ночная выгрузка, SQLite пускает одного
            # писателя), падать нельзя — иначе человек получает 500 на
            # странице входа, хотя вошёл успешно. Так и случилось 24.08:
            # запись ждала блокировку 30 секунд и не дождалась.
            try:
                user.last_login_at = datetime.utcnow()
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
                current_app.logger.warning(
                    "Не удалось записать время входа для %s: база занята. "
                    "Вход при этом выполнен.", user.username,
                )
            next_page = request.args.get("next")
            return redirect(next_page or url_for("hub.index"))
        flash("Неверный логин или пароль.", "danger")
    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("auth.login"))
