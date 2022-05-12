from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    token = StringField('Passwort', validators=[DataRequired()], render_kw={"placeholder": "Passwort"})
    submit = SubmitField('Login')