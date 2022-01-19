import os
from decouple import config
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    # SECRET_KEY = '\xec,\x1aK2RA\x05\x04\x89\x04-P\xda\xb9\xec\x04xcm\x8e\xfc\xcf,'
    SECRET_KEY = config('SECRET_KEY')
    # SQLALCHEMY_DATABASE_URI = "postgresql://flask_user:password@localhost/crud_users"
    SQLALCHEMY_DATABASE_URI = config('DATABASE_URL')
    # SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    # mail settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True

    # gmail authentication
    MAIL_USERNAME = config('APP_MAIL_USERNAME')
    MAIL_PASSWORD = config('APP_MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = config('APP_MAIL_USERNAME')
    SECURITY_PASSWORD_SALT = config('SECURITY_PASSWORD_SALT')


class ProductionConfig(Config):
    DEBUG = False


class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class TestingConfig(Config):
    TESTING = True