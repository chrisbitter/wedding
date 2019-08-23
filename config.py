import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    db_path = os.path.join(basedir, 'app.db')

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + db_path

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = '2ad2c50ba77a8e48db626cb10b8f172013d5aed697e31cf3'
    UPLOAD_FOLDER = os.path.join('static', 'pictures')
