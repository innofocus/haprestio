class Config(object):
    # haprestio configuration file

    # flask
    TESTING = False
    DEBUG = False
    PORT = '5080'
    HOST = 'localhost'

    # JWT
    JWT_TOKEN_LOCATION = 'headers'
    JWT_HEADER_TYPE = ''
    JWT_SECRET_KEY = 'super-secret'

    # restplus
    APIKEY_NAME = 'Authorization'

    # consul
    CONSUL_HOST = '127.0.0.1'
    CONSUL_PORT = '8500'

    # haproxy
    HASTATS_USER = 'haproxyuser'
    HASTATS_PASS = 'haproxypass'

    # haprestio files
    CONF_DIR = '.'
    PID_FILE = '/var/run/haprestio.pid'
    ACCOUNTS_FILE = 'accounts.yml'
    FQDNS_FILE = 'fqdns.yml'
    CERTS_DIR = 'certs'
    CERTS_EXT = '.pem'

    # user with admin role (password in accounts.yml or INITPASS)
    ADMINNAME = 'admin'
    INITPASS = 'admin'

    # functional
    INSTANCE = 'default'
    DEFAULT_LOCATION = '/api/v1'

    # consul templates

class ConfigTest(Config):
    TESTING = True
    DEBUG = True
    HOST = '0.0.0.0'
    CONSUL_HOST = 'consul-server-bootstrap'
    INSTANCE = "testing"

class ConfigDev(Config):
    TESTING = True
    DEBUG = True
    INSTANCE = "dev"