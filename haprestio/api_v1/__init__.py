
from flask import Blueprint
from flask_restplus import fields
from werkzeug.datastructures import FileStorage

from haprestio import *
from ..data.data import DataCasting, DataEndpoints

__all__ = ['certs', 'login', 'fqdns', 'pub']

blueprint = Blueprint('rapixy', __name__, url_prefix=app.config['DEFAULT_LOCATION'])
api_v1 = ProxyAPI(blueprint,
                  version=version_api,
                  title='Rapixy({})'.format(app.config['INSTANCE']),
                  description=description,
                  authorizations=authorizations,
                  security='apikey'
                  )
app.register_blueprint(api_v1.blueprint)

####
# accounts

get_token = api_v1.namespace('login', description='Login with tenant ID and Secret/Token to get an Authorization token',
                             ordered=True)
get_token_m = api_v1.model('login', {
    'Authorization': fields.String(readOnly=True,
                                   description="Used in Header within Authorization field (clic the green Authorize)")})


####
# Fqdns()
fqdn_ns = api_v1.namespace('fqdn', description='Fully Qualified Domain Name', ordered=True)
fqdn_m = api_v1.model('fqdn_request', {
    'fqdn': fields.String(required=True, description='FQDN frontend response', example='myapp.vpod.carrefour.com'),
    'state': fields.String(required=False, description='authorized values : ' + ' or '.join(DataCasting("").states),
                           default=DataCasting("").states['publish'], example=DataCasting("").states['publish']),
    'mode': fields.String(
        description='authorized values : ' + ' or '.join(DataEndpoints("", "").modes) + ' (passthrough)',
        required=False,
        default=DataEndpoints("", "").modes[0], example=DataEndpoints("", "").modes[0]),
    'subdomains': fields.String(
        description='authorized values : true or false. Redirect any subdomain when true',
        required=False,
        default="false", example="false"),
    'buggyclient': fields.String(
        description='authorized values : true or false. defines also a "fqdn:443". Seriously.',
        required=False,
        default="false", example="false"),
    'backend': fields.List(fields.String(required=False, description='Code for haproxy in backend section.'),
                           example=["balance roundrobin", "option ssl-hello-chk",
                                    "server srv01 10.0.0.10:443 weight 1 maxconn 100 check",
                                    "server srv02 10.0.0.11:443 weight 1 maxconn 100 check"]),
})
fqdn_mr = api_v1.inherit('fqdn_response', fqdn_m, {
    'message': fields.List(fields.String(
        description='messages from validation test (empty string when all is good)', default="''")),
    'spiid': fields.String(
        description='SuPport Information IDentifier. Give it to support call.')
})

####
# publisher
pub_ns = api_v1.namespace('publish', description='publish and unpublish defined fqdn or certificate', ordered=True)

####
# certs
cert_ns = api_v1.namespace('cert', description='Certificates manager', ordered=True)
cert_m = api_v1.model('cert_request', {
    'cert': fields.String(required=True, description='FQDN frontend response', example='myapp.vpod.carrefour.com'),
    'state': fields.String(required=False, description='authorized values : ' + ' or '.join(DataCasting("").states),
                           default='publish', example='publish'),
    'fqdn': fields.String(required=True, description='associated fqdn'),
})

cert_mr = api_v1.inherit('cert_response', cert_m, {
    'message': fields.List(fields.String(
        description='messages from validation test (empty string when all is good)', default="''")),
    'spiid': fields.String(
        description='SuPport Information IDentifier. Give it to support call.'),
    'content': fields.List(fields.String(), description='the jsonified content of the certificate')
})

upload_cert = cert_ns.parser()
upload_cert.add_argument('file', location='files',
                         type=FileStorage, required=True)
upload_cert.add_argument('name', required=True, help="The name of the certificate")


@api_v1.errorhandler
def default_error_handler(error):
    """Default error handler"""
    return {'message': error.message}, 401

