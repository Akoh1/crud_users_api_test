from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
import os
from decouple import config

# from .app import app, db
from app import app,db


# app.config.from_object(os.environ['APP_SETTINGS'])
app.config.from_object(config('APP_SETTINGS'))
# app.config.from_pyfile('config.py')
# app.config.from_object("config.DevelopmentConfig")


migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()