from flask_restplus import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt_claims

from . import pub_ns, fqdn_ns, fqdn_mr, fqdn_m, cert_mr
from ..data.data import DataCasting
from ..data.fqdns import Fqdns, Fqdn
from ..data.certs import Certs, Cert


@pub_ns.route('/fqdn', endpoint='publishfqdn')
@pub_ns.response(401, "Token has expired, bad credentials or reserved for administrators", fqdn_m)
class PublishFqdn(Resource):
    """fqdn publish"""

    @jwt_required
    @pub_ns.doc('publish', security='apikey')
    def put(self):
        """Publish all owned fqdn (only fqdn with state 'publish') """
        if get_jwt_claims()['roles'] == 'admin':
            return Fqdns().publish()
        return Fqdns().publish(get_jwt_identity())

    @jwt_required
    @pub_ns.doc('unpublish', security='apikey')
    def delete(self):
        """Unpublish all owned fqdn (state isnt modified)"""
        if get_jwt_claims()['roles'] == 'admin':
            return Fqdns().unpublish()
        return Fqdns().unpublish(get_jwt_identity())


@pub_ns.route('/fqdn/<string:fqdn>', endpoint='publishonefqdn')
@pub_ns.response(401, "Token has expired, bad credentials or reserved for administrators")
@pub_ns.response(409,
                 "'fqdn' fqdn is in state {}. Change it to make it publishable.".format(
                     DataCasting("").states['unpublish']))
@pub_ns.response(406, "Publish failed... There is a definition error in the fqdn.")
@pub_ns.response(202, "Publish success...")
class PublishOneFqdn(Resource):
    """fqdn publish"""

    @jwt_required
    @pub_ns.doc('publish one', security='apikey')
    @fqdn_ns.marshal_list_with(fqdn_mr)
    def put(self, fqdn):
        """Publish one owned fqdn (only fqdn with state 'publish') """

        if not Fqdn(fqdn).exists():
            pub_ns.abort(400, "can't publish non-existent fqdn")
        if Fqdn(fqdn).owner != get_jwt_identity() and get_jwt_claims()['roles'] != 'admin':
            pub_ns.abort(401, "you don't own this fqdn")

        f = Fqdn(fqdn)
        if f.is_unpublish():
            f.state = "publish"
            f.save()

        f = Fqdn(fqdn).publish()
        if f.is_publish():
            return f.json(), 202
        else:
            return f.json(), 406

    @jwt_required
    @pub_ns.doc('unpublish one', security='apikey')
    @fqdn_ns.marshal_list_with(fqdn_mr)
    def delete(self, fqdn):
        """Unpublish one owned fqdn (state isnt modified)"""

        if not Fqdn(fqdn).exists():
            pub_ns.abort(400, "can't publish non-existent fqdn")
        if Fqdn(fqdn).owner != get_jwt_identity() and get_jwt_claims()['roles'] != 'admin':
            pub_ns.abort(401, "you don't own this fqdn")

        f = Fqdn(fqdn).unpublish()
        if f.is_unpublish():
            return f.json(), 202
        else:
            return f.json(), 406


@pub_ns.route('/cert', endpoint='publishcerts')
@pub_ns.response(401, "Token has expired, bad credentials or reserved for administrators", fqdn_m)
class PublishCert(Resource):
    """Cert publish"""

    @jwt_required
    @pub_ns.doc('publish certificate', security='apikey')
    @pub_ns.marshal_list_with(cert_mr, mask='cert,state,fqdn,message')
    def put(self):
        """Publish all owned fqdn (only fqdn with state 'publish') """
        if get_jwt_claims()['roles'] == 'admin':
            return Certs().publish()
        return Certs().publish(get_jwt_identity())

    @jwt_required
    @pub_ns.doc('unpublish certificates', security='apikey')
    def delete(self):
        """Unpublish all owned fqdn (state isnt modified)"""
        if get_jwt_claims()['roles'] == 'admin':
            return Certs().unpublish()
        return Certs().unpublish(get_jwt_identity())


@pub_ns.route('/cert/<string:cert>', endpoint='publishonecert')
@pub_ns.response(401, "Token has expired, bad credentials or reserved for administrators")
@pub_ns.response(400, "can't publish non-existent certificate")
@pub_ns.response(406, "Publish failed... There is a definition error in the certificate.")
@pub_ns.response(202, "Publish success...")
class PublishOneCert(Resource):
    """ publish one certificate """

    @jwt_required
    @pub_ns.doc('publish one', security='apikey')
    @pub_ns.marshal_list_with(cert_mr, mask='cert,state,fqdn,message')
    def put(self, cert):
        """Publish one owned cert """

        if not Cert(cert).exists():
            pub_ns.abort(400, "can't publish non-existent certificate")
        if Cert(cert).owner != get_jwt_identity() and get_jwt_claims()['roles'] != 'admin':
            pub_ns.abort(401, "you don't own this certificate")

        c = Cert(cert).publish()
        if c.is_publish():
            return c.json(), 202
        else:
            return c.json(), 406

    @jwt_required
    @pub_ns.doc('unpublish one', security='apikey')
    @pub_ns.marshal_list_with(cert_mr, mask='cert,state,fqdn,message')
    def delete(self, cert):
        """Unpublish one owned cert """

        if not Cert(cert).exists():
            pub_ns.abort(400, "can't publish non-existent certificate")
        if Cert(cert).owner != get_jwt_identity() and get_jwt_claims()['roles'] != 'admin':
            pub_ns.abort(401, "you don't own this certificate")

        c = Cert(cert).unpublish()
        if c.is_publish():
            return c.json(), 202
        else:
            return c.json(), 406