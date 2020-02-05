import time
from flask import jsonify
from flask_restplus import Resource
from flask_jwt_extended import create_access_token

from . import get_token2, get_token2_m
from ..data.accounts import Account
from ..auth.jwt import admin_required

@get_token2.route('/name=<string:name>/password=<string:password>')
@get_token2.doc(security=[])
class UserLogin2(Resource):
    """Login with account credentials and get a temporary token"""

    @get_token2.doc(params={"name": "the tenant ID", "password": "the Secret/Token"})
    @get_token2.response(200,
                         'Success: Use the Authorization token in rest api call headers (clic the green Authorize) !',
                         get_token2_m)
    @get_token2.response(401, 'Bad credentials. Same player shoot again.')
    def get(self, name, password):
        """Login to retrieve a temporary Authorization token"""
        if not Account(name).exists():
            time.sleep(1)
            adm_v1.abort(401, "Bad credentials")
        if Account(name).check(password):
            access_token = create_access_token(identity=name)
            return jsonify(access_token=access_token)
        else:
            adm_v1.abort(401, "Bad credentials")


@get_token2.route('/impersonate=<string:name>')
class Impersonate(Resource):
    """Get account's token"""

    @admin_required
    @get_token2.doc(params={"name": "the tenant ID"})
    @get_token2.response(200,
                         'Success: Use the Authorization token in rest api call headers (clic the green Authorize) !',
                         get_token2_m)
    @get_token2.response(401, 'Bad credentials. Same player shoot again.')
    def get(self, name):
        """Get temporary Authorization token for account"""
        if not Account(name).exists():
            time.sleep(1)
            adm_v1.abort(401, "Bad account")
        access_token = create_access_token(identity=name)
        return jsonify(access_token=access_token)