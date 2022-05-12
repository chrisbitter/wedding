from models import Group, Guest, db
import logging
from flask import Flask

from config import Config

log_file = "app.log"

logging.basicConfig(filename=log_file, level=logging.DEBUG,
                    format="%(asctime)s\t\t%(levelname)s\t\t%(message)s")

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

if __name__ == "__main__":
    with app.app_context():
        guest = db.session.add(Guest(group_id=32, name='Willi', male=True))
        db.session.commit()
        app.logger.info(f"Add Guest: {guest}")

        guest = db.session.add(Guest(group_id=34, name='Astrid', male=False))
        db.session.commit()
        app.logger.info(f"Add Guest: {guest}")
