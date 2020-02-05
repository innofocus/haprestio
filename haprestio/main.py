#!/usr/bin/env python3

# pres side
from functools import wraps
from flask import Flask, jsonify, url_for, Response, Blueprint, redirect, request
from flask_restplus import Api, Resource, fields, marshal
from werkzeug.datastructures import FileStorage
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, verify_jwt_in_request, get_jwt_claims
)

# data side
import consul
import yaml
import os
import time

import datetime
import bcrypt
import subprocess
import requests
import csv
import json

# for backup onto google bucket
from google.cloud import storage

from . import *

from haprestio.api_v1 import api_v1
from haprestio.adm_v1 import adm_v1

####
# temp token
jwt = JWTManager(app)


@api_v1.errorhandler
def default_error_handler(error):
    """Default error handler"""
    return {'message': error.message}, 401


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


####
# data classes




####
# api namespaces


accts = Accounts(app.config['ADMINNAME'], app.config['INITPASS'])


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
            api_v1.abort(401, "Bad credentials")
        if Account(name).check(password):
            access_token = create_access_token(identity=name)
            return jsonify(access_token=access_token)
        else:
            api_v1.abort(401, "Bad credentials")


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
            api_v1.abort(401, "Bad account")
        access_token = create_access_token(identity=name)
        return jsonify(access_token=access_token)


@app.route('/')
def Redirect_slash():
    return redirect(app.config['DEFAULT_LOCATION'], code=302)


# @app.route('/<path:page>')
# def Redirect_all(page):
#    def_loc = app.config['DEFAULT_LOCATION'][1:]
#    print(page)
#    if not page.startswith(def_loc):
#        return redirect(def_loc+'/'+page, code=302)


@app.route('/maintenance')
def Maintenance():
    return Response(json.dumps({"message": "the api is in maintenance mode"}),
                    status=503,
                    mimetype='application/json')


@app.route('/pages/releasenotes')
def ReleaseNotes():
    return Response(releasenotes, status=200, mimetype='text/plain')


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
        return Account().create(api_v1.payload).json(), 201


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
        return Account(account).change(api_v1.payload['password'])


@fqdn_ns.route('', endpoint='fqdn')
@fqdn_ns.response(401, "Token has expired, bad credentials or reserved for administrators")
@fqdn_ns.response(201, "Successfully created")
@fqdn_ns.response(409, "Can't create already present 'fqdn' fqdn")
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
            fqdn_ns.abort(409, "Can't create already present 'fqdn' fqdn")
            return
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


########
# adm and ops

@ops_ns.route('/load_users', endpoint='ops_users')
class Ops_users_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc('Reload accounts from config file', security='apikey')
    def get(self):
        """ Load users from users.yml"""
        return Accounts().load_yaml(app.config['CONF_DIR'] + '/' + app.config['ACCOUNTS_FILE'])


@ops_ns.route('/load_fqdns', endpoint='ops_fqdns')
class Ops_fqdns_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc('Reload fqdns from config file', security='apikey')
    def get(self):
        """ Load users from fqdns.yml"""
        Fqdns().load_yaml(app.config['CONF_DIR'] + '/' + app.config['FQDNS_FILE'])
        return Fqdns().publish()


@ops_ns.route('/load_certs', endpoint='ops_certs')
class Ops_certs_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc('Reload certificates from config file', security='apikey')
    def get(self):
        """ Load users from certs"""
        result = Certs().load_dir(app.config['CONF_DIR'] + '/' + app.config['CERTS_DIR'])
        Certs().publish()
        return result


@ops_ns.route('/load_localpipe', endpoint='ops_localpipe')
class Ops_localpipe_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc('Load localpipe configuration from file (be careful, not test in here !)', security='apikey')
    def get(self):
        """ Load localpipe from config"""
        return Config('localpipe').load_file(app.config['CONF_DIR'], 'localpipe.cfg')


@ops_ns.route('/import_json', endpoint='ops_import_json')
class Ops_import_json_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.expect(upload_json)
    @ops_ns.doc('Import additive consul keys from json file', security='apikey')
    def post(self):
        """ Import additive consul keys from json file"""
        args = upload_json.parse_args()
        uploaded_file = args['file']
        dest_file = '/tmp/import.json'
        with open(dest_file, 'w') as f:
            f.write(uploaded_file.stream.read().decode('utf-8'))
            f.close()

        return Operations().import_file(dest_file)


@ops_ns.route('/export_json', endpoint='ops_export_json')
class Ops_export_json_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc('export consul database in json format', security='apikey')
    def get(self):
        """ export  consul database in json format"""
        return Operations().export_json()


@ops_ns.route('/backup', endpoint='backup_json')
class Backup_R(Resource):
    """" Administratives operations on backups"""

    @admin_required
    @ops_ns.doc('backup consul database in json format on gcp bucket', security='apikey')
    def put(self):
        """ backup consul database in json format on gcp bucket """
        return Operations().backup_json()

    @admin_required
    @ops_ns.doc('list backups from gcp bucket', security='apikey')
    def get(self):
        """ list backups from gcp bucket """
        return Operations().backup_list()


@ops_ns.route('/restore/<string:backupname>', endpoint='restore_json')
class Restore_R(Resource):
    """" Administratives operations on restore"""

    @admin_required
    @ops_ns.doc('restore backup from gcp bucket', security='apikey')
    def post(self, backupname):
        """ restore consul database from gcp bucket backups"""
        return Operations().restore_json(backupname=backupname)


@ops_ns.route('/jilt', endpoint='ops_jilt')
class Ops_jilt_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc("Check nodes for removal from gcp lb4 for maintenance purpose", security='apikey')
    def get(self):
        """ jilt get status"""
        return Operations().get_jilt()


@ops_ns.route('/jilt/me', endpoint='ops_jilt_me')
class Ops_jilt_me_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc('Remove this node from gcp lb4 for maintenance purpose', security='apikey')
    def put(self):
        """ jilt me"""
        return Operations().jilt_me()

    @admin_required
    @ops_ns.doc('Get this node back to gcp lb4 after maintenance', security='apikey')
    def get(self):
        """ unjilt me"""
        return Operations().unjilt_me()


@ops_ns.route('/jilt/group', endpoint='ops_jilt_group')
class Ops_jilt_group_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc("Remove all group's nodes from gcp lb4 for maintenance purpose", security='apikey')
    def put(self):
        """ jilt group"""
        return Operations().jilt_group()

    @admin_required
    @ops_ns.doc("Get all group's nodes back to gcp lb4 after maintenance", security='apikey')
    def get(self):
        """ unjilt group"""
        return Operations().unjilt_group()


@ops_ns.route('/maintenance', endpoint='ops_maintenance')
class Maintenance_R(Resource):
    """" Administratives operations"""

    @admin_required
    @ops_ns.doc("Put api in maintenance mode", security='apikey')
    def put(self):
        """ maintenance ON"""
        return Operations().maintenance_on()

    @admin_required
    @ops_ns.doc("Remove api maintenance mode", security='apikey')
    def get(self):
        """ maintenance OFF"""
        return Operations().maintenance_off()

def main():
    # modules
    from haprestio.operations import parser, install

    if parser.args.install:
        install.templates(parser.args)
        exit(0)

    if app.config['DEBUG']:
        app.run(debug=True, host=app.config['HOST'], port=app.config['PORT'])
    else:
        app.run(host=app.config['HOST'], port=app.config['PORT'])