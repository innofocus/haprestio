import time
from flask import jsonify
from flask_restplus import Resource
from flask_jwt_extended import create_access_token

from . import get_token, get_token_m
from ..data.accounts import Account

@get_token.route('/name=<string:name>/password=<string:password>')
@get_token.doc(security=[])
class UserLogin(Resource):
    """Login with account credentials and get a temporary token"""

    @get_token.doc(params={"name": "the tenant ID", "password": "the Secret/Token"})
    @get_token.response(200,
                        'Success: Use the Authorization token in rest api call headers (clic the green Authorize) !',
                        get_token_m)
    @get_token.response(401, 'Bad credentials. Same player shoot again.')
    def get(self, name, password):
        """Login to retrieve a temporary Authorization token"""
        if not Account(name).exists():
            time.sleep(1)
            api_v1.abort(401, "Bad credentials")
        if Account(name).check(password):
            access_token = create_access_token(identity=name)
            return jsonify(access_token=access_token)
        else:
            api_v1.abort(401, "Bad credentials")