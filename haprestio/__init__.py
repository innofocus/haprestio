__all__ = ['haprestio']
import os
from flask import Flask

# app instance
if os.path.exists('/etc/rapixy/haprestio.cfg'):
    app = Flask(__name__, instance_path='/etc/rapixy', instance_relative_config=True)
else:
    app = Flask(__name__, instance_path="%s/%s" % (os.path.dirname(__file__), '/data'), instance_relative_config=True)

# app config
app.config.from_pyfile('haprestio.cfg')
app.wsgi_app = ProxyFix(app.wsgi_app)

import haprestio.main
from haprestio.operations import *
