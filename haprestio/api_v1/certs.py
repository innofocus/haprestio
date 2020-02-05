import logging
from flask_restplus import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt_claims
from . import cert_ns, cert_m, cert_mr, upload_cert
from ..data.certs import Certs, Cert

@cert_ns.route('', endpoint='cert')
@cert_ns.response(401, "Token has expired, bad credentials or reserved for administrators", cert_m)
@cert_ns.response(406, "Data validation error")
@cert_ns.response(201, "Certificate file uploaded", cert_m)
class Certs_R(Resource):
    """certificates upload"""

    @jwt_required
    @cert_ns.doc('upload certificate', security='apikey')
    @cert_ns.expect(upload_cert)
    @cert_ns.marshal_with(cert_mr, mask='cert,state,fqdn,message')
    def post(self):
        """upload new or existing certificate object"""
        args = upload_cert.parse_args()
        cert_content = args['file'].getvalue().decode('utf-8')
        owner = get_jwt_identity()
        cert_name = args['name']

        logging.info(" Uploading cert {}".format(cert_name))

        # load file to consul
        loadok, cn = Certs().load_content(cert_content)

        # first step for importing
        if not loadok:
            logging.info("Import {} error: invalid certificate".format(cert_name))
            return {
                       "cert": cert_name,
                       "state": "not_imported",
                       "fqdn": "",
                       "message": [
                           "Import {} error: invalid certificate".format(cert_name),
                           " Reason: {}".format(cn)],
                       "spiid": ""
                   }, 406

        # second step with publish
        Cert(cert_name).update({"owner": owner, "content": cert_content,
                                "state": 'publish', "fqdn": cn})
        c = Cert(cert_name).publish()
        if c.is_publish():
            return c.json(), 201
        else:
            return c.json(), 406

    @jwt_required
    @cert_ns.doc('List owned certs entries', security='apikey')
    @cert_ns.marshal_list_with(cert_mr, mask='cert,state,fqdn,message')
    def get(self):
        """get certificate list"""
        if get_jwt_claims()['roles'] == 'admin':
            return Certs().json(), 200
        return Certs().json(get_jwt_identity())


@cert_ns.route('/<string:cert>', endpoint='certone')
@cert_ns.response(401, "Token has expired, bad credentials or reserved for administrators", cert_m)
@cert_ns.response(400, "can't publish non-existent certificate")
class Certs_R(Resource):
    """certificate modification"""

    @jwt_required
    @cert_ns.doc('Remove a certificate', security='apikey')
    @cert_ns.marshal_with(cert_mr, mask='cert,state,fqdn,message')
    def delete(self, cert):
        """delete certificate"""
        if not Cert(cert).exists():
            cert_ns.abort(400, "can't delete non-existent certificate")
        if Cert(cert).owner != get_jwt_identity() and get_jwt_claims()['roles'] != 'admin':
            cert_ns.abort(401, "you don't own this certificate")
        return Cert(cert).unpublish().json()
