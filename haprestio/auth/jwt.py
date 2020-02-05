from flask_jwt_extended import verify_jwt_in_request, get_jwt_claims
from functools import wraps

from . import jwt
from .. import app
from ..api_v1 import api_v1

# jwt admin role
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except:
            api_v1.abort(401, "Missing Authorization Header")

        claims = get_jwt_claims()
        if claims['roles'] != 'admin':
            api_v1.abort(401, "Token has expired, bad credentials or reserved for administrators")
        else:
            return fn(*args, **kwargs)

    return wrapper


@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    if identity == app.config['ADMINNAME']:
        return {'roles': 'admin'}
    else:
        return {'roles': 'client'}

