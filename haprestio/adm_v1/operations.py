import logging
from flask_restplus import Resource
from .. import app
from . import ops_ns, upload_json
from ..operations.operations import Operations
from ..data import Accounts
from ..data.fqdns import Fqdns
from ..data.certs import Certs
from ..auth.jwt import admin_required
from ..helpers.helpers import Config


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