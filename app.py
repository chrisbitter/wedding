import argparse
import logging
import os
import random
from http import HTTPStatus
from urllib.parse import urlparse, urljoin

import flask
import pandas as pd
from flask import Flask, render_template, url_for, redirect, request, jsonify
from flask_login import LoginManager, login_required, \
    current_user as current_group, login_user, logout_user

from config import Config
from forms import LoginForm

parser = argparse.ArgumentParser(description="Wedding Website")
parser.add_argument("--init", action='store_true', help="Initialize Service.")
args, leftovers = parser.parse_known_args()

path_events = "resources/events.csv"
path_guest_list = "resources/guests.csv"
path_gifts = "resources/gifts.csv"
path_images_home = "static/img/home"
path_images_thanks = "static/img/thanks"
path_images_fotobox = "static/img/fotobox"
path_images_fotograph = "static/img/fotograph"
path_images_drone = "static/img/drone"
path_images_gifts = "static/img/gifts"
log_file = "app.log"

logging.basicConfig(filename=log_file, level=logging.DEBUG,
                    format="%(asctime)s\t\t%(levelname)s\t\t%(message)s")

app = Flask(__name__)
app.config.from_object(Config)

from models import Group, Guest, Gift, db

db.init_app(app)


# with app.app_context():
#     # db.drop_all()
#     db.create_all()


def create_group(df_group):
    name = df_group.group.values[0]
    standesamt = df_group.standesamt.values[0]
    token = df_group.token.values[0]

    group = Group(name=name, standesamt=standesamt == 1., token=token)

    db.session.add(group)
    db.session.commit()

    app.logger.info(f"Add Group: {group}")

    for _, guest in df_group.iterrows():
        guest = Guest(group_id=group.id, name=guest["name"], male=guest.male)
        db.session.add(guest)
        db.session.commit()

        app.logger.info(f"Add Guest: {guest}")


if args.init:

    app.logger.info("Initialize database")

    with app.app_context():
        db.drop_all()
        db.create_all()

        group_name = "Team Nerz"
        token = "WuselSchmusel.agency"
        group = Group(name=group_name, token=token, admin=True,
                      standesamt=True)
        db.session.add(group)
        db.session.commit()

        db.session.add(Guest(group_id=group.id, name='Kristina', male=False))
        db.session.add(Guest(group_id=group.id, name='Christian', male=True))
        db.session.commit()

        df_guests = pd.read_csv(path_guest_list, sep=";", encoding='latin1')

        df_guests.dropna(axis=0, how='all', inplace=True)
        df_guests.dropna(axis=1, how='all', inplace=True)

        group_indices = list(df_guests.group.dropna().index.values)

        group_indices.append(df_guests.shape[0])

        for idxA, idxB in zip(group_indices[:-1], group_indices[1:]):
            df_group = df_guests.loc[idxA:idxB - 1]

            create_group(df_group)

    exit()

with app.app_context():
    db.create_all()

    df_gifts = pd.read_csv(path_gifts)

    for gift_index, gift_row in df_gifts.iterrows():
        gift_dict = gift_row.to_dict()
        gift_dict["image"] = os.path.join(path_images_gifts,
                                          gift_dict["image"])

        gift = Gift.query.filter_by(id=gift_index).first()

        if not gift:
            gift = Gift(**gift_dict)
        else:

            for key, value in gift.serialize.items():
                if key in gift_dict:
                    setattr(gift, key, gift_dict[key])

        db.session.add(gift)
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


def get_events_information(group_events=None):
    events_information = pd.read_csv(path_events)

    events_information.color = events_information.color.apply(eval)

    events_information["id"] = events_information.index

    events_information = events_information.to_dict(orient="records")

    if group_events is not None:
        events_information = [event for event in events_information if
                              event["id"] in group_events]

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
    return redirect(url_for('thanks'))


@app.route('/thanks')
@login_required
def thanks():
    group = current_group

    users = get_users(group.id)

    images = [os.path.join(path_images_thanks, img) for img in
              os.listdir(path_images_thanks)]

    random.shuffle(images)

    is_admin = current_group.is_admin()

    return render_template('thanks.html', title='031020',
                           active_page="thanks", is_admin=is_admin,
                           images=images, group_name=group.name, users=users)


@app.route('/pictures')
@login_required
def pictures():
    group = current_group

    users = get_users(group.id)

    images_fotobox = [os.path.join(path_images_fotobox, img) for img in
              os.listdir(path_images_fotobox)][:50]

    images_fotograph = [os.path.join(path_images_fotograph, img) for img in
              os.listdir(path_images_fotograph)]

    images_drone = [os.path.join(path_images_drone, img) for img in
              os.listdir(path_images_drone)]

    random.shuffle(images_fotobox)
    random.shuffle(images_fotograph)
    random.shuffle(images_drone)

    is_admin = current_group.is_admin()

    return render_template('pictures.html', title='031020',
                           active_page="pictures", is_admin=is_admin,
                           images_fotobox=images_fotobox,
                           images_fotograph=images_fotograph,
                           images_drone=images_drone,
                           group_name=group.name, users=users)
#
#
# @app.route('/download_fotobox')
# def download_fotobox ():
#     path = "/Examples.pdf"
#     return send_file(path, as_attachment=True)

@app.route('/home')
@login_required
def home():
    group = current_group

    users = get_users(group.id)

    images = [os.path.join(path_images_home, img) for img in
              os.listdir(path_images_home)]

    random.shuffle(images)

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

    gifts = [gift.serialize for gift in Gift.query.all()]

    gifts_reserved_self = []
    gifts_reserved = []
    gifts_unreserved = []

    for gift in gifts:
        if gift["group_id"]:
            if gift["group_id"] == current_group.id:
                gifts_reserved_self.append(gift)
            else:
                gifts_reserved.append(gift)
        else:
            gifts_unreserved.append(gift)

    gifts_sorted = gifts_reserved_self + gifts_unreserved + gifts_reserved

    return render_template('gifts.html', title='Wünsche', active_page="gifts",
                           group_id=current_group.id, gifts=gifts_sorted,
                           is_admin=is_admin)


@app.route('/reserve_gift', methods=['POST'])
@login_required
def reserve_gift():
    gift_id = request.form["gift_id"]

    gift = Gift.query.filter_by(id=gift_id).first()

    gift.group_id = current_group.id

    db.session.commit()

    app.logger.info(f"Update Gift {gift}")

    return "", HTTPStatus.NO_CONTENT


@app.route('/unreserve_gift', methods=['POST'])
@login_required
def unreserve_gift():
    gift_id = request.form["gift_id"]

    gift = Gift.query.filter_by(id=gift_id).first()

    gift.group_id = None

    db.session.commit()

    app.logger.info(f"Update Gift {gift}")

    return "", HTTPStatus.NO_CONTENT


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

    return render_template('hotels.html', title='Hotels',
                           events_information=events_information,
                           active_page="hotels", is_admin=is_admin)


@app.route('/overview')
@login_required
def overview():
    if current_group.is_admin():
        groups = get_all_groups()

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

        app.logger.info(f"Add group: {group}")

        group_id = group.id

        for user_name in user_names:
            guest = Guest(group_id=group_id, name=user_name)
            db.session.add(guest)

            app.logger.info(f"Add guest: {guest}")

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
    app.logger.debug(f"Logout {current_group}")

    logout_user()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_group.is_authenticated:
        return redirect(url_for('rsvp'))

    form = LoginForm()

    if form.validate_on_submit():

        group = Group.query.filter_by(token=form.token.data).first()

        app.logger.debug(f"Login {group}")

        if group is None:  # or not user.check_password(form.password.data):
            return redirect(url_for('login'))
        else:
            next = flask.request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.

            if not is_safe_url(next):
                return flask.abort(400)

            login_user(group)

            return flask.redirect(next or flask.url_for('home'))
    return flask.render_template('login.html', form=form, title='Login')


@app.errorhandler(404)
def page_not_found(e):
    # your processing here
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, port=5050)
    # waitress.serve(app, host="0.0.0.0", port=5050)
    # waitress.serve(app, host="0.0.0.0", port=5050, url_scheme='https')
