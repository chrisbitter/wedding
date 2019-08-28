import flask
from flask import Flask, render_template, flash, url_for, redirect, request
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from sqlalchemy.exc import IntegrityError
from forms import LoginForm
from http import HTTPStatus
import logging
from urllib.parse import urlparse, urljoin
from config import Config
import csv

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

#logger.setLevel(logging.DEBUG)

path_agenda = "resources/agenda.csv"


app = Flask(__name__)
app.config.from_object(Config)

from models import Group, User, db

db.init_app(app)


try:
    with app.app_context():

        db.drop_all()
        db.create_all()

        group_name = "Familie Nerz"
        token = "nerz"

        group = Group(name=group_name, token_hash=hash(token))
        db.session.add(group)

        group_id = Group.query.filter_by(name=group_name).first().id

        nerz1 = User(group_id=group_id, name='Sir Nerz')
        nerz2 = User(group_id=group_id, name='Nerzdame')
        db.session.add(nerz1)
        db.session.add(nerz2)
        db.session.commit()

        # users = User.query.filter_by(group_id=group_id).all()

except IntegrityError:
    logger.warning("Database already initialized with admin account")

def get_users(group_id):
    users = User.query.with_entities(User.id, User.name, User.rsvp,
                                     User.food_choice).filter_by(
        group_id=group_id).all()

    users = [{"id": user[0], "name": user[1], "rsvp": user[2],
              "food_choice": user[3]} for user in users]

    return users

def get_agenda():
    with open(path_agenda) as f:

        agenda_items = [{"name": name, "time": time} for name, time in csv.reader(f, delimiter='\t')]

    return agenda_items

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.route('/agenda')
@login_required
def agenda():

    agenda_items = get_agenda()

    return render_template('agenda.html', title='Agenda', active_page="agenda", agenda_items=agenda_items)

@app.route('/')
@app.route('/rsvp')
@login_required
def rsvp():
    group = current_user

    users = get_users(group.id)

    print(users)

    return render_template('rsvp.html', title='RSVP', active_page="rsvp", group_name=group.name, users=users)

@app.route("/update_rsvp", methods=['POST'])
@login_required
def update_rsvp():

    guest_id = request.form["id"]
    choice = request.form["choice"]

    user = User.query.filter_by(id=guest_id).first()

    user.rsvp = choice == "true"

    db.session.commit()

    return "", HTTPStatus.NO_CONTENT

@app.route('/location')
@login_required
def location():
    return render_template('location.html', title='Location', active_page="location")




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
    if current_user.is_authenticated:
        return redirect(url_for('agenda'))
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm()

    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
        # login_user(user)

        group = Group.query.filter_by(token_hash=hash(form.token.data)).first()

        if group is None: # or not user.check_password(form.password.data):
            return redirect(url_for('login'))
        else:
            logger.debug("login successful")

            next = flask.request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.

            logger.debug(next)
            logger.debug(is_safe_url(next))

            if not is_safe_url(next):
                return flask.abort(400)

            login_user(group)

            return flask.redirect(next or flask.url_for('rsvp'))
    return flask.render_template('login.html', form=form, title='Login')



if __name__ == '__main__':

    app.run(debug=True, use_reloader=False)