from flask_restplus import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt_claims
from . import tenant, tenant_m, adm_v1
from ..auth.jwt import admin_required
from ..data.accounts import Accounts, Account
from ..data import accts

@tenant.route('')
@tenant.response(401, "Token has expired, bad credentials or reserved for administrators")
class Accounts_R(Resource):
    """Shows a list of all accounts, and lets you POST to add new account"""

    @admin_required
    @tenant.doc('list_accounts', security='apikey')
    @tenant.marshal_list_with(tenant_m)
    def get(self):
        """List all accounts"""
        return Accounts().dict()

    @admin_required
    @tenant.doc('create_account', security='apikey')
    @tenant.expect(tenant_m)
    # @tenant.marshal_with(tenant_m, code=201)
    def post(self):
        """Create a new account"""
        return Account().create(adm_v1.payload).json(), 201


@tenant.route('/<string:account>')
@tenant.response(404, 'Account not found')
@tenant.response(401, "Token has expired, bad credentials or reserved for administrators")
@tenant.response(409, "Can't create already present 'account' account")
@tenant.response(406, "Data payload error. Please ensure options.")
@tenant.param('account', 'The account name')
class Account_R(Resource):
    """Show a single account item"""

    @jwt_required
    @tenant.doc('get_account')
    @tenant.marshal_with(tenant_m)
    def get(self, account):
        """Fetch a given account"""
        if get_jwt_identity() != account and get_jwt_claims()['roles'] != 'admin':
            tenant.abort(401, "bad credentials")
        if not accts.exists(account):
            tenant.abort(404, 'Account not found')
        return Account(account).json()

    @admin_required
    @tenant.doc('delete_account')
    @tenant.response(204, 'Account deleted')
    def delete(self, account):
        """Delete an account given its name"""
        return Account(account).delete()

    @jwt_required
    @tenant.expect(tenant_m)
    @tenant.marshal_with(tenant_m)
    def put(self, account):
        """Update an account given its name"""
        if get_jwt_identity() != account and get_jwt_claims()['roles'] != 'admin':
            tenant.abort(401, "bad credentials")
        if not accts.exists(account):
            tenant.abort(404, 'Account not found')
        return Account(account).change(adm_v1.payload['password'])
