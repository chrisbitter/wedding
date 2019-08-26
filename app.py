import flask
from flask import Flask, render_template, flash, url_for, redirect, request
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from sqlalchemy.exc import IntegrityError
from forms import LoginForm
import os
import logging
from urllib.parse import urlparse, urljoin
from config import Config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

#logger.setLevel(logging.DEBUG)

app = Flask(__name__)
app.config.from_object(Config)

from models import User, db

db.init_app(app)


try:
    with app.app_context():

        db.drop_all()
        db.create_all()

        admin = User(username='admin', password_hash=hash("a"))
        db.session.add(admin)
        db.session.commit()
except IntegrityError:
    logger.warning("Database already initialized with admin account")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.route('/agenda')
@login_required
def agenda():
    return render_template('agenda.html', title='Agenda', active_page="agenda")

@app.route('/')
@login_required
def rsvp():
    return render_template('rsvp.html', title='RSVP', active_page="rsvp")

@app.route('/location')
@login_required
def location():
    return render_template('location.html', title='Location', active_page="location")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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

    # logger.debug(form.username.data)

    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
        # login_user(user)
        user = User.query.filter_by(username=form.username.data).first()

        if user is None or not user.check_password(form.password.data):
            # flash('Invalid username or password')
            return redirect(url_for('login'))
        else:
            # flask.flash('Logged in successfully.')

            logger.debug("login successful")

            next = flask.request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.

            logger.debug(next)
            logger.debug(is_safe_url(next))

            if not is_safe_url(next):
                return flask.abort(400)

            login_user(user)

            return flask.redirect(next or flask.url_for('agenda'))
    return flask.render_template('login.html', form=form, title='Login')



if __name__ == '__main__':

    app.run(debug=True, use_reloader=False)