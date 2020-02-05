import yaml
__all__ = ['accounts', 'certs', 'data', 'endpoints', 'fqdns', 'DataModel', "accts"]

DataModel = yaml.safe_load("""\
haproxy:
  casting:
    config:
      localpipe:
        - opt_content
    accounts:
      login:
        - password
    fqdns:
      fqdn:
        - fqdn
        - mode
        - subdomains
        - buggyclient
        - frontex
        - extended
        - owner
        - state
        - backend
        - message
        - spiid
    certs:
       cert:
         - cert
         - state
         - owner
         - fqdn
         - content
         - message
         - spiid
  stages:
    certs:
       name:
        - content
    frontends-http:
       name:
         - content
    frontends-tcp:
       name:
         - content
    frontends-http-extended:
       name:
         - content
    frontends-tcp-extended:
       name:
         - content
    backend-http:
       name:
         - content
    backend-tcp:
       name:
         - content
""")

from .accounts import Accounts
from .. import app

accts = Accounts(app.config['ADMINNAME'], app.config['INITPASS'])

