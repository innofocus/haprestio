#!/usr/bin/env python3

from . import *

def main():

    from . import api_v1
    api_v1.init()

    from . import adm_v1
    adm_v1.init()

    if app.config['DEBUG']:
        app.run(debug=True, host=app.config['HOST'], port=app.config['PORT'])
    else:
        app.run(host=app.config['HOST'], port=app.config['PORT'])
