import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'PASSWORD'
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.qq.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '465'))
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'true').lower() in \
        ['true', 'on', '1']
    MAIL_USERNAME = 'xxx'
    MAIL_PASSWORD = 'xxx'
    FLASKY_MAIL_SUBJECT_PREFIX = '[Echo]'
    FLASKY_MAIL_SENDER = 'Echo Admin<1012216781@qq.com>'
    FLASKY_ADMIN = os.environ.get('1012216781@qq.com')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


config = {
    'development': DevelopmentConfig,
    'default': DevelopmentConfig
}
