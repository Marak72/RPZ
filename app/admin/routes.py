"""Учётные записи сотрудников и доступ к сервисам портала.

Администратор заводит учётную запись, назначает роль и отмечает, какие
сервисы сотрудник видит. Роль отвечает за то, что можно делать
(`оператор` меняет данные, `просмотр` только смотрит), а список сервисов —
за то, что вообще показывается: и в переключателе, и на страницах.
"""
from __future__ import annotations

from datetime import datetime
from functools import wraps

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from ..extensions import db
from ..models import ROLE_ADMIN, ROLES, User, UserService
from ..portal import SERVICES
from .forms import PasswordForm, ProfileForm, UserForm

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(view):
    """Раздел учётных записей доступен только администраторам."""

    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _service_choices() -> list:
    return [(svc.id, f"{svc.title} — {svc.subtitle}") for svc in SERVICES]


def _apply_grants(user: User, service_ids) -> None:
    """Привести список доступных сервисов к выбранному."""
    wanted = {s for s in (service_ids or []) if s in {svc.id for svc in SERVICES}}
    current = {g.service_id: g for g in user.grants}

    for service_id in wanted - set(current):
        db.session.add(UserService(user_id=user.id, service_id=service_id))
    for service_id in set(current) - wanted:
        db.session.delete(current[service_id])


# --- Список и карточки ----------------------------------------------------

@admin_bp.route("/users")
@admin_required
def users():
    return render_template(
        "admin/users.html",
        items=User.query.order_by(User.is_enabled.desc(), User.username).all(),
        services=SERVICES,
        roles=dict(ROLES),
    )


@admin_bp.route("/users/new", methods=["GET", "POST"])
@admin_required
def user_new():
    form = UserForm()
    form.services.choices = _service_choices()
    if not form.services.data:
        # Новому сотруднику по умолчанию открыты все сервисы: сузить проще,
        # чем разбираться, почему у него пустой портал.
        form.services.data = [svc.id for svc in SERVICES]

    if form.validate_on_submit():
        username = form.username.data.strip()
        if User.query.filter_by(username=username).first():
            flash(f"Учётная запись «{username}» уже существует.", "danger")
            return render_template("admin/user_form.html", form=form, user=None)
        if not form.password.data:
            flash("Задайте пароль для новой учётной записи.", "danger")
            return render_template("admin/user_form.html", form=form, user=None)

        user = User(
            username=username,
            full_name=(form.full_name.data or "").strip(),
            position=(form.position.data or "").strip(),
            email=(form.email.data or "").strip(),
            role=form.role.data,
            is_enabled=form.is_enabled.data,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        _apply_grants(user, form.services.data)
        db.session.commit()
        flash(f"Учётная запись «{username}» создана.", "success")
        return redirect(url_for("admin.users"))

    return render_template("admin/user_form.html", form=form, user=None)


@admin_bp.route("/users/<int:user_id>", methods=["GET", "POST"])
@admin_required
def user_edit(user_id: int):
    user = db.get_or_404(User, user_id)
    form = UserForm(obj=user)
    form.services.choices = _service_choices()
    if request.method == "GET":
        form.services.data = sorted(user.allowed_services())

    if form.validate_on_submit():
        username = form.username.data.strip()
        clash = User.query.filter(User.username == username,
                                  User.id != user.id).first()
        if clash:
            flash(f"Логин «{username}» уже занят.", "danger")
            return render_template("admin/user_form.html", form=form, user=user)

        # Страховка от самоблокировки: последний администратор должен остаться.
        if user.id == current_user.id:
            if form.role.data != ROLE_ADMIN:
                flash("Нельзя снять с себя роль администратора.", "danger")
                return render_template("admin/user_form.html", form=form, user=user)
            if not form.is_enabled.data:
                flash("Нельзя отключить собственную учётную запись.", "danger")
                return render_template("admin/user_form.html", form=form, user=user)
        elif user.is_admin and form.role.data != ROLE_ADMIN and _admin_count() <= 1:
            flash("Это последний администратор — роль менять нельзя.", "danger")
            return render_template("admin/user_form.html", form=form, user=user)

        user.username = username
        user.full_name = (form.full_name.data or "").strip()
        user.position = (form.position.data or "").strip()
        user.email = (form.email.data or "").strip()
        user.role = form.role.data
        user.is_enabled = form.is_enabled.data
        if form.password.data:
            user.set_password(form.password.data)
        _apply_grants(user, form.services.data)
        db.session.commit()
        flash(f"Учётная запись «{user.username}» сохранена.", "success")
        return redirect(url_for("admin.users"))

    return render_template("admin/user_form.html", form=form, user=user)


def _admin_count() -> int:
    return User.query.filter_by(role=ROLE_ADMIN, is_enabled=True).count()


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def user_toggle(user_id: int):
    """Включить или отключить учётную запись, не удаляя её."""
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("Нельзя отключить собственную учётную запись.", "danger")
        return redirect(url_for("admin.users"))
    if user.is_enabled and user.is_admin and _admin_count() <= 1:
        flash("Это последний администратор — отключать нельзя.", "danger")
        return redirect(url_for("admin.users"))

    user.is_enabled = not user.is_enabled
    db.session.commit()
    flash(
        f"Учётная запись «{user.username}» "
        f"{'включена' if user.is_enabled else 'отключена'}.",
        "success",
    )
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def user_delete(user_id: int):
    """Удаление. Обычно правильнее отключить — записи в журналах ссылаются на УЗ."""
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("Нельзя удалить собственную учётную запись.", "danger")
        return redirect(url_for("admin.users"))
    if user.is_admin and _admin_count() <= 1:
        flash("Это последний администратор — удалять нельзя.", "danger")
        return redirect(url_for("admin.users"))

    name = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"Учётная запись «{name}» удалена.", "success")
    return redirect(url_for("admin.users"))


# --- Свой профиль ---------------------------------------------------------

@admin_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Свои реквизиты и смена пароля — доступно любому сотруднику."""
    profile_form = ProfileForm(obj=current_user)
    password_form = PasswordForm()

    if profile_form.submit_profile.data and profile_form.validate_on_submit():
        current_user.full_name = (profile_form.full_name.data or "").strip()
        current_user.position = (profile_form.position.data or "").strip()
        current_user.email = (profile_form.email.data or "").strip()
        db.session.commit()
        flash("Профиль сохранён.", "success")
        return redirect(url_for("admin.profile"))

    if password_form.submit_password.data and password_form.validate_on_submit():
        if not current_user.check_password(password_form.current.data):
            flash("Текущий пароль указан неверно.", "danger")
            return render_template("admin/profile.html",
                                   profile_form=profile_form,
                                   password_form=password_form,
                                   services=SERVICES)
        current_user.set_password(password_form.password.data)
        db.session.commit()
        flash("Пароль изменён.", "success")
        return redirect(url_for("admin.profile"))

    return render_template(
        "admin/profile.html",
        profile_form=profile_form,
        password_form=password_form,
        services=SERVICES,
    )


def touch_last_login(user: User) -> None:
    """Отметить вход — вызывается из формы авторизации."""
    user.last_login_at = datetime.utcnow()
    db.session.commit()
