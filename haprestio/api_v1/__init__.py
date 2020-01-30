from flask import Blueprint
from haprestio import *

blueprint = Blueprint('rapixy', __name__, url_prefix=app.config['DEFAULT_LOCATION'])
api_v1 = ProxyAPI(blueprint,
                  version=version_api,
                  title='Rapixy({})'.format(app.config['INSTANCE']),
                  description=description,
                  authorizations=authorizations,
                  security='apikey'
                  )
app.register_blueprint(api_v1.blueprint)