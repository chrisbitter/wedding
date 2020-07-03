import os
from http import HTTPStatus
from urllib.parse import urlparse, urljoin

import flask
import pandas as pd
from flask import Flask, render_template, url_for, redirect, request, jsonify
from flask_login import LoginManager, login_required, \
    current_user as current_group, login_user, logout_user

from config import Config
from forms import LoginForm

path_agenda = "resources/agenda.csv"
path_events = "resources/events.csv"
path_images = "static/img"

app = Flask(__name__)
app.config.from_object(Config)

from models import Group, Guest, db

db.init_app(app)

debug = True

if debug:
    with app.app_context():
        db.drop_all()
        db.create_all()

        events_all = "[0,1,2,3]"
        events_limited = "[0,1,3]"

        # only for debugging
        group_id = 0
        group_name = "Team Nerz"
        token = "nerz"
        group = Group(id=group_id, name=group_name, token=token, admin=True,
                      standesamt=True)
        db.session.add(group)
        nerz1 = Guest(group_id=group_id, name='Kristina Bitter')
        nerz2 = Guest(group_id=group_id, name='Christian Scheiderer')
        db.session.add(nerz1)
        db.session.add(nerz2)
        db.session.commit()

        group_id = 1
        group_name = "Familie Dachs"
        token = "dachs"
        group = Group(id=group_id, name=group_name, token=token,
                      standesamt=True)
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
        group = Group(id=group_id, name=group_name, token=token,
                      standesamt=False)
        db.session.add(group)
        fuchs = Guest(group_id=group_id, name='Mr. Fuchs')
        db.session.add(fuchs)
        db.session.commit()


def get_group_events(group_id):
    group_events = eval(Group.query.with_entities(Group.events).filter_by(
        id=group_id).first()[0])

    return group_events


def get_users(group_id):
    users = Guest.query.with_entities(Guest.id, Guest.name, Guest.male,
                                      Guest.rsvp).filter_by(
        group_id=group_id).all()

    group_events = get_group_events(group_id)

    users = [{"id": user[0], "name": user[1], "male": user[2],
              "rsvp": {event: rsvp for event, rsvp in enumerate(eval(user[3]))
                       if
                       event in group_events}} for user in
             users]

    return users


def get_all_groups():
    groups = Group.query.all()

    result = []

    for group in groups:

        group_id = group.id
        group_name = group.name
        group_events = get_group_events(group_id)

        if group.is_admin():
            group_token = None
        else:
            group_token = group.token

        users = get_users(group_id)

        group_data = {"id": group_id, "name": group_name, "token": group_token,
                      "users": users, "events": group_events}

        result.append(group_data)

    return result


def get_agenda():
    agenda = pd.read_csv(path_agenda)

    agenda_items = agenda.to_dict(orient="records")

    return agenda_items


def get_events_information(group_events=None):
    events_information = pd.read_csv(path_events)

    events_information.color = events_information.color.apply(eval)

    events_information["id"] = events_information.index

    events_information = events_information.to_dict(orient="records")

    if group_events is not None:
        events_information = [event for event in events_information if
                              event["id"] in group_events]

    print(events_information)


    return events_information


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@app.route('/agenda')
@login_required
def agenda():
    group = current_group

    group_events = get_group_events(group.id)

    events_information = get_events_information(group_events)

    is_admin = current_group.is_admin()

    return render_template('agenda.html', title='Agenda', active_page="agenda",
                           events_information=events_information,
                           is_admin=is_admin)


@app.route('/')
def index():
    # redirect(url_for('rsvp'))
    return redirect(url_for('home'))


@app.route('/home')
@login_required
def home():
    group = current_group

    users = get_users(group.id)

    images = [os.path.join(path_images, img) for img in
              os.listdir(path_images)]

    is_admin = current_group.is_admin()

    return render_template('home.html', title='031020',
                           active_page="home", is_admin=is_admin,
                           images=images, group_name=group.name, users=users)


@app.route('/rsvp')
@login_required
def rsvp():
    group = current_group

    users = get_users(group.id)

    group_events = get_group_events(group.id)

    events_information = get_events_information(group_events)

    is_admin = current_group.is_admin()

    return render_template('rsvp.html', title='RSVP', active_page="rsvp",
                           group_name=group.name,
                           events_information=events_information, users=users,
                           is_admin=is_admin)


@app.route("/update_rsvp", methods=['POST'])
@login_required
def update_rsvp():
    guest_id = request.form["guest_id"]
    event_id = int(request.form["event_id"])
    choice = request.form["choice"]

    if choice == "":
        choice = None
    else:
        choice = choice == "true"

    user = Guest.query.filter_by(id=guest_id).first()

    rsvp = eval(user.rsvp)

    rsvp[event_id] = choice

    user.rsvp = repr(rsvp)

    db.session.commit()

    app.logger.info(f"Update RSVP {user}")

    return "", HTTPStatus.NO_CONTENT


@app.route('/gifts')
@login_required
def gifts():
    is_admin = current_group.is_admin()

    return render_template('gifts.html', title='Wünsche',
                           active_page="gifts", is_admin=is_admin)



@app.route('/corona')
@login_required
def corona():
    is_admin = current_group.is_admin()

    return render_template('corona.html', title='Corona',
                           active_page="corona", is_admin=is_admin)


@app.route('/hotels')
@login_required
def hotels():
    group = current_group

    group_events = get_group_events(group.id)

    events_information = get_events_information(group_events)

    is_admin = current_group.is_admin()

    return render_template('hotels.html', title='Hotels', events_information=events_information,
                           active_page="hotels", is_admin=is_admin)


@app.route('/overview')
@login_required
def overview():
    if current_group.is_admin():
        groups = get_all_groups()

        print(groups)

        is_admin = current_group.is_admin()

        return render_template('overview.html', title='Overview',
                               active_page="overview", groups=groups,
                               is_admin=is_admin)
    else:
        return redirect(url_for('login'))


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
        return redirect(url_for('rsvp'))

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


@app.errorhandler(404)
def page_not_found(e):
    # your processing here
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
