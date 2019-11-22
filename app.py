import flask
from flask import Flask, render_template, url_for, redirect, request, jsonify
from flask_login import LoginManager, login_required, \
    current_user as current_group, login_user, logout_user
from sqlalchemy.exc import IntegrityError
from forms import LoginForm
from http import HTTPStatus
import logging
from urllib.parse import urlparse, urljoin
from config import Config
import csv
import pandas as pd

path_agenda = "resources/agenda.csv"

app = Flask(__name__)
app.config.from_object(Config)

from models import Group, Guest, db

db.init_app(app)

debug = True

if debug:
    with app.app_context():
        db.drop_all()
        db.create_all()

        # only for debugging
        group_id = 0
        group_name = "Team Nerz"
        token = "nerz"
        group = Group(id=group_id, name=group_name, token=token, admin=True)
        db.session.add(group)
        nerz1 = Guest(group_id=group_id, name='Kristina Bitter')
        nerz2 = Guest(group_id=group_id, name='Christian Scheiderer')
        db.session.add(nerz1)
        db.session.add(nerz2)
        db.session.commit()

        group_id = 1
        group_name = "Familie Dachs"
        token = "dachs"
        group = Group(id=group_id, name=group_name, token=token)
        db.session.add(group)
        dachs1 = Guest(group_id=group_id, name='Sir Dachs')
        dachs2 = Guest(group_id=group_id, name='Mrs Dachs')
        dachs3 = Guest(group_id=group_id, name='Frechdachs')
        db.session.add(dachs1)
        db.session.add(dachs2)
        db.session.add(dachs3)
        db.session.commit()

        group_id = 2
        group_name = "Fuchs"
        token = "fuchs"
        group = Group(id=group_id, name=group_name, token=token)
        db.session.add(group)
        fuchs = Guest(group_id=group_id, name='Mr. Fuchs')
        db.session.add(fuchs)
        db.session.commit()


def get_users(group_id):
    users = Guest.query.with_entities(Guest.id, Guest.name,
                                      Guest.rsvp).filter_by(
        group_id=group_id).all()

    users = [{"id": user[0], "name": user[1], "rsvp": user[2]} for user in
             users]

    return users


def get_all_groups():
    groups = Group.query.all()

    result = []

    for group in groups:

        group_id = group.id
        group_name = group.name

        if group.is_admin():
            group_token = None
        else:
            group_token = group.token

        users = get_users(group_id)

        group_data = {"id": group_id, "name": group_name, "token": group_token,
                      "users": users}

        result.append(group_data)

    return result


def get_agenda():
    agenda = pd.read_csv(path_agenda)

    agenda_items = agenda.to_dict(orient="records")

    return agenda_items


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@app.route('/agenda')
@login_required
def agenda():
    agenda_items = get_agenda()

    is_admin = current_group.is_admin()

    return render_template('agenda.html', title='Agenda', active_page="agenda",
                           agenda_items=agenda_items, is_admin=is_admin)


@app.route('/')
@login_required
def welcome():
    group = current_group

    users = get_users(group.id)

    is_admin = current_group.is_admin()

    return render_template('welcome.html', title='031020',
                           active_page="welcome", is_admin=is_admin)


@app.route('/rsvp')
@login_required
def rsvp():
    group = current_group

    users = get_users(group.id)

    is_admin = current_group.is_admin()

    return render_template('rsvp.html', title='RSVP', active_page="rsvp",
                           group_name=group.name, users=users,
                           is_admin=is_admin)


@app.route("/update_rsvp", methods=['POST'])
@login_required
def update_rsvp():
    guest_id = request.form["id"]
    choice = request.form["choice"]

    if choice == "":
        choice = None
    else:
        choice = choice == "true"

    user = Guest.query.filter_by(id=guest_id).first()

    user.rsvp = choice

    db.session.commit()

    app.logger.info(f"Update RSVP {user}")

    return "", HTTPStatus.NO_CONTENT


@app.route('/location')
@login_required
def location():
    is_admin = current_group.is_admin()

    return render_template('location.html', title='Location',
                           active_page="location", is_admin=is_admin)


@app.route('/overview')
@login_required
def overview():
    if current_group.is_admin():
        groups = get_all_groups()

        is_admin = current_group.is_admin()

        return render_template('overview.html', title='Overview',
                               active_page="overview", groups=groups,
                               is_admin=is_admin)


@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    if current_group.is_admin():

        group_name = str(request.form["name"])
        token = str(request.form["token"])
        user_names = request.form.getlist("user_names[]")

        user_names = [str(name) for name in user_names if name != ""]

        if len(user_names) == 1:
            group_name = user_names[0]

        group = Group(name=group_name, token=token)
        db.session.add(group)
        db.session.commit()

        app.logger.info(f"Create group {group}")

        group_id = group.id

        for user_name in user_names:
            guest = Guest(group_id=group_id, name=user_name)
            db.session.add(guest)

            app.logger.info(f"Create guest {guest}")

        db.session.commit()

        users = get_users(group_id)

        group_data = {"id": group_id, "name": group_name, "token": token,
                      "users": users}

        return jsonify(group_data)


@app.route('/delete_group', methods=['POST'])
@login_required
def delete_group():
    if current_group.is_admin():

        group_id = request.form["id"]

        groups = Group.query.filter_by(id=group_id).all()
        guests = Guest.query.filter_by(group_id=group_id).all()

        for group in groups:
            app.logger.info(f"Delete {group}")
            db.session.delete(group)

        for guest in guests:
            app.logger.info(f"Delete {guest}")
            db.session.delete(guest)

        db.session.commit()

        return "", HTTPStatus.NO_CONTENT

    else:
        return "", HTTPStatus.UNAUTHORIZED


@login_manager.user_loader
def load_user(group_id):
    return Group.query.get(int(group_id))


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_group.is_authenticated:
        return redirect(url_for('agenda'))

    form = LoginForm()

    if form.validate_on_submit():

        group = Group.query.filter_by(token=form.token.data).first()

        app.logger.info(f"Login {group}")

        if group is None:  # or not user.check_password(form.password.data):
            return redirect(url_for('login'))
        else:
            app.logger.debug("login successful")

            next = flask.request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.

            app.logger.debug(next)
            app.logger.debug(is_safe_url(next))

            if not is_safe_url(next):
                return flask.abort(400)

            login_user(group)

            return flask.redirect(next or flask.url_for('rsvp'))
    return flask.render_template('login.html', form=form, title='Login')


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
