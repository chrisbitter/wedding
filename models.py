from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    token = db.Column(db.String, unique=True)
    admin = db.Column(db.Boolean, default=False)
    events = db.Column(db.String, default="[0,1,3]")

    def __init__(self, **kwargs):

        standesamt = kwargs.pop("standesamt", False)

        if standesamt:
            kwargs["events"] = "[0,1,2,3]"
        else:
            kwargs["events"] = "[0,1,3]"

        super(Group, self).__init__(**kwargs)
        # do custom initialization here

    def __repr__(self):
        return f'Group <{self.name} | id {self.id} | Admin {self.admin}>'

    def is_active(self):
        """True, as all groups are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id

    def is_authenticated(self):
        """Return True if the group is authenticated."""
        return True

    def is_anonymous(self):
        """False, as anonymous groups aren't supported."""
        return False

    def is_admin(self):
        return self.admin


class Guest(db.Model):
    __tablename__ = 'guest'

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    name = db.Column(db.String)
    male = db.Column(db.Boolean, default=True)
    rsvp = db.Column(db.String, default="[None, None, None, None]")

    # food_choice = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'Guest <{self.name} | {"male" if self.male else "female"} | Group {self.group_id} | RSVP {self.rsvp}>'

    def check_password(self, password):
        return self.password_hash == str(hash(password))
