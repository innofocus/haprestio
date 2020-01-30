from flask import Blueprint
from haprestio import *

blueprint2 = Blueprint('rapixy_ops', __name__, url_prefix='/adm')
adm_v1 = ProxyAPI(blueprint2,
                  version=version_api,
                  title='Rapixy({})'.format(app.config['INSTANCE']),
                  description=description,
                  authorizations=authorizations,
                  security='apikey'
                  )
app.register_blueprint(adm_v1.blueprint)