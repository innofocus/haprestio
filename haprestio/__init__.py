__all__ = ['haprestio']
import os
from flask import Flask

# services instance
if os.path.exists('/etc/rapixy/rapixy.cfg'):
    app = Flask(__name__, instance_path='/etc/rapixy', instance_relative_config=True)
else:
    app = Flask(__name__)

import haprestio.main
from haprestio.operations import *