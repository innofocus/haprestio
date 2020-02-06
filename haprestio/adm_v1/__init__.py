from flask import Blueprint
from flask_restplus import fields
from werkzeug.datastructures import FileStorage

from haprestio import *
__all__ = ['accounts', 'login', 'operations']

blueprint2 = Blueprint('rapixy_ops', __name__, url_prefix='/adm')
adm_v1 = ProxyAPI(blueprint2,
                  version=version_api,
                  title='Rapixy({})'.format(app.config['INSTANCE']),
                  description=description,
                  authorizations=authorizations,
                  security='apikey'
                  )

####
# accounts

get_token2 = adm_v1.namespace('login',
                              description='Login with tenant ID and Secret/Token to get an Authorization token',
                              ordered=True)
get_token2_m = adm_v1.model('login', {
    'Authorization': fields.String(readOnly=True,
                                   description="Used in Header within Authorization field (clic the green Authorize)")})
tenant = adm_v1.namespace('account', description='Rapixy account (reserved for Ops operations)', ordered=True)
tenant_m = adm_v1.model('account', {
    'login': fields.String(readOnly=True, description='The tenant ID as an Rapixy account'),
    'password': fields.String(required=True, description='The Secret/Token as Rapixy account\'s password')
})


####
# adminops

ops_ns = adm_v1.namespace('ops', description='Administrative operations', ordered=True)

upload_json = ops_ns.parser()
upload_json.add_argument('file', location='files',
                         type=FileStorage, required=True)

from . import *

def init():
    app.register_blueprint(adm_v1.blueprint)