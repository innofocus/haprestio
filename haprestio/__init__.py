__all__ = ['app', 'ProxyAPI', 'version_api', 'releasenotes', 'description', 'authorizations']
import os, logging
from flask import Flask, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_restplus import Api

from haprestio.operations import arguments

####
# error hanlding
FORMAT = "[%(levelname)s:%(pathname)s:%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)

# app instance
logging.info("looking for: {}/haprestio.cfg".format(arguments.args.install_dir))

if os.path.exists("{}/haprestio.cfg".format(arguments.args.install_dir)):
    app = Flask(__name__, instance_path=arguments.args.install_dir, instance_relative_config=True)
else:
    logging.info("{}/haprestio.cfg not found".format(arguments.args.install_dir))
    app = Flask(__name__, instance_path="%s/%s" % (os.path.dirname(__file__), '/data'), instance_relative_config=True)

logging.info("using configuration dir: {}".format(app.instance_path))
# app config
app.config.from_pyfile('haprestio.cfg')
app.wsgi_app = ProxyFix(app.wsgi_app)


# prepare version, releasenotes, tag

consul_template_tag = ""
if os.path.exists('/opt/consul-template/templates/'):
    consul_template_tag = str(int(os.path.getmtime('/opt/consul-template/templates/')))

with open('haprestio/infos/version.txt') as f:
    version = f.read().split('.')

version_num = ".".join(version[0:3])
version_aka = version[3]

with open('haprestio/infos/ReleaseNotes.md') as f:
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

# Bug when https protocole used
class ProxyAPI(Api):
    @property
    def specs_url(self):
        """
        The Swagger specifications absolute url (ie. `swagger.json`)

        :rtype: str
        """
        return url_for(self.endpoint('specs'), _external=False)

# defines access control type
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': app.config['APIKEY_NAME']
    }
}

import haprestio.main
from haprestio.operations import *
