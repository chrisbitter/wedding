from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    token_hash = db.Column(db.String, unique=True)
    admin = db.Column(db.Boolean, default=False)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return True

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def is_admin(self):
        return self.admin

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    name = db.Column(db.String)
    rsvp = db.Column(db.Boolean, nullable=True)
    food_choice = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<{self.name} | Group {self.group_id} | RSVP {self.rsvp} | Food {self.food_choice}>'

    def check_password(self, password):
        return self.password_hash == str(hash(password))