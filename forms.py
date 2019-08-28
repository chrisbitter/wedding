from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    token = StringField('Token', validators=[DataRequired()], render_kw={"placeholder": "Token"})
    submit = SubmitField('Login')