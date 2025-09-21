from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   # from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route('/services')
def services():
    return render_template("services.html")

@auth.route('/contact')
def contact():
    return render_template("contact.html")

@auth.route('/about-us')
def about():
    return render_template("about.html")

@auth.route('/reservation')
@login_required
def reservation():
    if current_user.is_admin:
        from .models import Reservation
        reservations = Reservation.query.all()
        return render_template("admin_reservations.html", reservations=reservations, user=current_user)
    else:
        return render_template("reservation.html", user=current_user)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email') or ""
        first_name = request.form.get('firstName') or ""
        last_name = request.form.get('lastName') or ""
        password1 = request.form.get('password1') or ""
        password2 = request.form.get('password2') or ""

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif len(last_name) < 2:
            flash('Last name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=generate_password_hash(password1, method='pbkdf2:sha256')
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)


@auth.route('/profile')
@login_required
def profile():
    return render_template("profile.html", user=current_user)


@auth.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    user = User.query.get(current_user.id)
    if user:
        logout_user()
        db.session.delete(user)
        db.session.commit()
        flash("Your account has been deleted.", "info")
    return redirect(url_for('views.home'))

@auth.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if not check_password_hash(current_user.password, current_password):
        flash("Current password is incorrect.", category="error")
        return redirect(url_for("auth.profile"))

    if new_password != confirm_password:
        flash("New passwords do not match.", category="error")
        return redirect(url_for("auth.profile"))

    if len(new_password) < 7:
        flash("New password must be at least 7 characters long.", category="error")
        return redirect(url_for("auth.profile"))

    current_user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
    db.session.commit()

    flash("Password updated successfully!", category="success")
    return redirect(url_for("auth.profile"))