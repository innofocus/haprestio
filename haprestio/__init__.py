from flask_restplus import Api
from flask import Flask, url_for, redirect, Response
from werkzeug.middleware.proxy_fix import ProxyFix
import os, json, logging
from .config import config

__all__ = ['app', 'ProxyAPI', 'authorizations', 'description', 'version_api', 'version_num', 'version', 'version_aka', 'releasenotes']


# Bug when https protocole used
class ProxyAPI(Api):
    @property
    def specs_url(self):
        """
        The Swagger specifications absolute url (ie. `swagger.json`)

        :rtype: str
        """
        return url_for(self.endpoint('specs'), _external=False)

####
# error hanlding
FORMAT = "[ %(levelname)s:%(pathname)s:%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)


#  config info
logging.info("Default config file: {}".format(os.path.dirname(__file__) + "/config.py"))

# instance app
if os.getenv('HAPRESTIO_CFG'):
    instance_path, config_file = os.path.split(os.getenv('HAPRESTIO_CFG'))
    if config_file == "":
        config_file="haprestio.cfg"
    app = Flask(__name__, instance_path=instance_path, instance_relative_config=True)
    app.config.from_object(config.Config())

    if not os.path.exists(os.getenv('HAPRESTIO_CFG')):
        logging.info('no configuration file found at {}'.format(os.getenv('HAPRESTIO_CFG')))
        logging.info('using {} as configuration template'.format(os.getenv('HAPRESTIO_ENV')))
        from .operations import install
        install.install(instance_path, os.getenv("HAPRESTIO_ENV"), 'UWSGI' in app.config and not app.config['UWSGI'])
        install.deploy(instance_path)
        logging.info(('configurations files generated at {}.\n please run again to launch.'.format(os.getenv('HAPRESTIO_CFG'))))
        exit(0)
    app.config.from_pyfile(config_file)
    logging.info("Config overloaded from {}".format(os.getenv('HAPRESTIO_CFG')))
else:
    app = Flask(__name__)
    app.config.from_object(config.Config())


# app config
app.wsgi_app = ProxyFix(app.wsgi_app)

# prepare version, releasenotes, tag

consul_template_tag = ""
if os.path.exists('{}/consul-template/templates/'.format(app.instance_path)):
    consul_template_tag = str(int(os.path.getmtime('{}/consul-template/templates/'.format(app.instance_path))))

#####
# vresions infos
install_source = '/'.join(__file__.split('/')[0:-2])
with open('{}/haprestio/infos/version.txt'.format(install_source)) as f:
    version = f.read().split('.')

version_num = ".".join(version[0:3])
version_aka = version[3]

with open('{}/haprestio/infos/ReleaseNotes.md'.format(install_source)) as f:
    releasenotes = f.read().format(version_num=version_num, version_aka=version_aka)
    f.close()

description = """
<a href=/pages/releasenotes>Release Notes</a>
---
Instance  : {instance}
Version   : {version}
Deploy tag: {version_tag}""".format(instance=app.config['INSTANCE'],
                                    version=version_num,
                                    version_tag=consul_template_tag)

version_api = 'v{} aka "{}"'.format(version_num, version_aka)
logging.info("haprestio version: {}".format(version_api))

# defines access control type
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': app.config['APIKEY_NAME']
    }
}

@app.route('/')
def Redirect_slash():
    return redirect(app.config['DEFAULT_LOCATION'], code=302)

@app.route('/maintenance')
def Maintenance():
    return Response(json.dumps({"message": "the api is in maintenance mode"}),
                    status=503,
                    mimetype='application/json')

@app.route('/pages/releasenotes')
def ReleaseNotes():
    return Response(releasenotes, status=200, mimetype='text/plain')

import haprestio.main
