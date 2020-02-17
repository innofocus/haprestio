from flask_restplus import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt_claims
from . import api_v1, fqdn_ns, fqdn_m, fqdn_mr
from ..data.fqdns import Fqdns, Fqdn
from ..helpers.helpers import Haproxy


@fqdn_ns.route('', endpoint='fqdn')
@fqdn_ns.response(401, "Token has expired, bad credentials or reserved for administrators")
@fqdn_ns.response(201, "Successfully created")
@fqdn_ns.response(409, "Can't create already THIS  present 'fqdn' fqdn")
@fqdn_ns.response(406, "Error on definition content, please rewrite your definition")
class Fqdns_R(Resource):
    """Shows a list of all Fqdns(), and lets you POST to add new fqdn"""

    @jwt_required
    @fqdn_ns.doc('list_frontends', security='apikey')
    @fqdn_ns.marshal_list_with(fqdn_mr)
    def get(self):
        """List all fqdn entries that you own."""
        if get_jwt_claims()['roles'] == 'admin':
            return Fqdns().json()
        return Fqdns().json(get_jwt_identity())

    @jwt_required
    @fqdn_ns.doc('Add Frontend fqdn', security='apikey')
    @fqdn_ns.expect(fqdn_m)
    @fqdn_ns.marshal_with(fqdn_mr)
    def post(self):
        """Create a new fqdn entry"""
        api_v1.payload.update({'owner': get_jwt_identity()})
        if Fqdn(api_v1.payload['fqdn']).exists():
            return { 'message': "Can't create WTF already present 'fqdn' fqdn"}, 409
        f = Fqdn().create(api_v1.payload)
        if not f.is_publish_fail():
            return f.json(), 201
        else:
            f.destroy()
            f.state = "publish_failed"
            return f.json(), 406


@fqdn_ns.route('/<string:fqdn>', endpoint='fqdnchange')
@fqdn_ns.response(400, "can't get or modify non-existent fqdn")
@fqdn_ns.response(401, "Token has expired, bad credentials or reserved for administrators")
@fqdn_ns.response(409, "Can't modify not present 'fqdn' fqdn")
@fqdn_ns.response(200, "Operation is successful")
class Fqdn_R(Resource):
    """Modify fqdn"""

    @jwt_required
    @fqdn_ns.doc('show fqdn', security='apikey')
    @fqdn_ns.marshal_with(fqdn_mr)
    def get(self, fqdn):
        """Show a fqdn entry that you own"""
        result = Fqdn(fqdn)
        if not result.exists():
            fqdn_ns.abort(400, "can't get non-existent fqdn")
        if get_jwt_claims()['roles'] == 'admin' or get_jwt_identity() == result.owner:
            return result.json()

    @jwt_required
    @fqdn_ns.doc('update fqdn', security='apikey')
    @fqdn_ns.expect(fqdn_m)
    @fqdn_ns.marshal_with(fqdn_mr)
    def put(self, fqdn):
        """Modify a fqdn entry that you own"""
        if not Fqdn(fqdn).exists():
            fqdn_ns.abort(400, "can't modify non-existent fqdn")
        if Fqdn(fqdn).owner != get_jwt_identity() and get_jwt_claims()['roles'] != 'admin':
            fqdn_ns.abort(401, "you don't own this fqdn")
        f = Fqdn(fqdn).update(api_v1.payload)
        if f.is_publish_fail():
            return f.json(), 406
        else:
            return f.json(), 201

    @jwt_required
    @fqdn_ns.doc('remove fqdn', security='apikey')
    @fqdn_ns.marshal_with(fqdn_mr)
    # @tenant.response(204, 'fqdn deleted (set state to remove)')
    def delete(self, fqdn):
        """definitly remove a fqdn entry that you own from this service."""
        if not Fqdn(fqdn).exists():
            fqdn_ns.abort(400, "can't modify non-existent fqdn")
        if Fqdn(fqdn).owner != get_jwt_identity() and get_jwt_claims()['roles'] != 'admin':
            fqdn_ns.abort(401, "you don't own this fqdn")
        return Fqdn(fqdn).destroy().json()


@fqdn_ns.route('/<string:fqdn>/hastats')
@fqdn_ns.response(400, "can't get non-existent fqdn")
@fqdn_ns.response(401, "Token has expired, bad credentials or reserved for administrators")
@fqdn_ns.response(200, "Operation is successful")
class Hastats_R(Resource):
    """Haproxy stats"""

    @jwt_required
    @fqdn_ns.doc("show backend's fqdn full stats", security='apikey')
    def get(self, fqdn):
        """Show backend's fqdn full stats that you own"""
        result = Fqdn(fqdn)
        if not result.exists():
            fqdn_ns.abort(400, "can't get stats on non-existent fqdn")
        if get_jwt_claims()['roles'] == 'admin' or get_jwt_identity() == result.owner:
            return Haproxy().getstats(result.backend_name)


@fqdn_ns.route('/<string:fqdn>/status')
@fqdn_ns.response(400, "can't get non-existent fqdn")
@fqdn_ns.response(401, "Token has expired, bad credentials or reserved for administrators")
@fqdn_ns.response(200, "Operation is successful")
class Hastatus_R(Resource):
    """Haproxy status"""

    @jwt_required
    @fqdn_ns.doc("show backend's fqdn short status", security='apikey')
    def get(self, fqdn):
        """Show backend's fqdn short status"""
        result = Fqdn(fqdn)
        if not result.exists():
            fqdn_ns.abort(400, "can't get stats on non-existent fqdn")
        if get_jwt_claims()['roles'] == 'admin' or get_jwt_identity() == result.owner:
            return Haproxy().getstatus(result.backend_name)
