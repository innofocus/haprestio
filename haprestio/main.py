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
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
import bcrypt
import subprocess
import requests
import csv
import json

# for backup onto google bucket
from google.cloud import storage

from . import app

# show version consul_template config
consul_template_tag = ""
if os.path.exists('/opt/consul-template/templates/'):
    consul_template_tag = str(int(os.path.getmtime('/opt/consul-template/templates/')))

with open('haprestio/infos/version.txt') as f:
    version = f.read().split('.')
version_num = ".".join(version[0:3])
version_aka = version[3]
description = """
<a href=/pages/releasenotes>Release Notes</a>
---
Instance  : {instance}
Version   : {version}
Deploy tag: {version_tag}""".format(instance=app.config['INSTANCE'],
                                    version=version_num,
                                    version_tag=consul_template_tag)

with open('haprestio/infos/ReleaseNotes.md') as f:
    releasenotes = f.read().format(version_num=version_num, version_aka=version_aka)
    f.close()

class ProxyAPI(Api):
    @property
    def specs_url(self):
        """
        The Swagger specifications absolute url (ie. `swagger.json`)

        :rtype: str
        """
        return url_for(self.endpoint('specs'), _external=False)


authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': app.config['APIKEY_NAME']
    }
}

blueprint = Blueprint('rapixy', __name__, url_prefix=app.config['DEFAULT_LOCATION'])
api = ProxyAPI(blueprint,
               version='v{} aka "{}"'.format(version_num, version_aka),
               title='Rapixy({})'.format(app.config['INSTANCE']),
               description=description,
               authorizations=authorizations,
               security='apikey'
               )
app.register_blueprint(api.blueprint)

blueprint2 = Blueprint('rapixy_ops', __name__, url_prefix='/adm')
api2 = ProxyAPI(blueprint2,
                version='v{} aka "{}"'.format(version_num, version_aka),
                title='Rapixy({})'.format(app.config['INSTANCE']),
                description=description,
                authorizations=authorizations,
                security='apikey'
                )
app.register_blueprint(api2.blueprint)

jwt = JWTManager(app)

# serviceability
if 'UWSGI' in app.config and not app.config['UWSGI']:
    logging.info("Creating PID file.")
    fh = open(app.config['PID_FILE'], "w")
    fh.write(str(os.getpid()))
    fh.close()

####
# data instance
concon = consul.Consul(app.config['CONSUL_HOST'], app.config['CONSUL_PORT'])


####
# error hanlding
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)


@api.errorhandler
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
            api.abort(401, "Missing Authorization Header")

        claims = get_jwt_claims()
        if claims['roles'] != 'admin':
            api.abort(401, "Token has expired, bad credentials or reserved for administrators")
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


DataModel = yaml.safe_load("""\
haproxy:
  casting:
    config:
      localpipe:
        - opt_content
    accounts:
      login:
        - password
    fqdns:
      fqdn:
        - fqdn
        - mode
        - subdomains
        - buggyclient
        - frontex
        - extended
        - owner
        - state
        - backend
        - message
        - spiid
    certs:
       cert:
         - cert
         - state
         - owner
         - fqdn
         - content
         - message
         - spiid
  stages:
    certs:
       name:
        - content
    frontends-http:
       name:
         - content
    frontends-tcp:
       name:
         - content
    frontends-http-extended:
       name:
         - content
    frontends-tcp-extended:
       name:
         - content
    backend-http:
       name:
         - content
    backend-tcp:
       name:
         - content
""")



class ConsulTemplate(object):
    def __init__(self, spiid):
        _ct_path = "/opt/consul-template/bin/consul-template"
        _ct_template = "/opt/consul-template/templates/haproxy-testing.cfg.ctmpl"
        _ct_options = "-once -template"
        self.spiid = spiid
        self.rendered = "/tmp/{}.cfg".format(spiid)
        self.ct_command = '{} {} {}:{}'.format(_ct_path, _ct_options, _ct_template, self.rendered)
        _test_path = "sudo /usr/sbin/haproxy"
        _test_options = "-c -V -f /etc/haproxy/haproxy.cfg -f "
        self.test_command = '{} {} {}'.format(_test_path, _test_options, self.rendered)
        self.returncode = 0
        self.returnerr = ""

    def render(self):
        ret = subprocess.run(self.ct_command.split(),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             env={'SPIID': self.spiid})
        logging.info("stderr: {}".format(ret.stderr.decode("utf-8") + '\n' + ret.stdout.decode("utf-8")))
        if ret.returncode != 0:
            return False, ret.stderr.decode("utf-8")
        return True, ""

    def validate(self):
        ret = subprocess.run(self.test_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.returncode = ret.returncode
        self.returnerr = ret.stderr.decode("utf-8")

        logging.info("retcode: {}; stderr: {}".format(self.returncode, self.returnerr))
        if ret.returncode != 0:
            return False
        return True

    def cleanup(self):
        try:
            # os.remove(self.rendered)
            pass
        except:
            logging.warning(" fail to remove {}".format(self.rendered))

    def evaluation(self):
        ret, err = self.render()
        if not ret:
            return False
        ret = self.validate()
        self.cleanup()
        return ret


class Haproxy(object):
    def __init__(self):
        nodes = concon.agent.agent.catalog.nodes()
        nodeslist = []
        for n in nodes[1]:
            nodeslist.append({'node': n['Node'], 'addr': n['Address']})
        self.nodes = nodeslist
        self.port = '8282'
        self.user = app.config['HASTATS_USER']
        self.password = app.config['HASTATS_PASS']

    def getstats(self, backend, filter=None):
        url = "http://{}:{}/?stats;csv;scope={}"
        ret = []
        for node in self.nodes:
            host = node['node']
            response = requests.get(
                url.format(node['addr'], self.port, backend),
                auth=(self.user, self.password)
            )
            logging.info(response.content[2:].decode('utf-8'))
            if response.status_code == 200:
                dictdata = []
                csvdata = csv.DictReader(response.content[2:].decode('utf-8').splitlines(), delimiter=',')
                for col in csvdata:
                    colstat = {}
                    svname = col['svname']
                    if isinstance(filter, list):
                        for c in col.keys():
                            if c in filter:
                                colstat.update({c: col[c]})
                    else:
                        colstat = col
                    dictdata.append({'svname': svname, 'stats': colstat})
                ret.append({'node': node['node'], 'data': dictdata})
            else:
                ret.append({'node': node['node'], 'data': "Error fetching datas: haproxy stats status_code {}".format(
                    str(response.status_code))})
        return {backend: ret}

    def getstatus(self, backend):
        status = self.getstats(backend,
                               filter=['status', 'lastchg', 'downtime', 'addr', 'check_desc', 'check_code', 'last_chk',
                                       'check_status'])
        ret = {}
        for s in status[backend]:
            for i in s:
                if i == "data":
                    for d in s[i]:
                        t = ""
                        if d['svname'] in ret:
                            t = ret[d['svname']]
                        nstatus = "/" + d['stats']['status'] + "(" + d['stats']['check_desc'] + ")"
                        if t != nstatus:
                            ret.update({d['svname']: t + nstatus})
        return ret


class ConsulDataMixin(object):
    """ Mixin for Consulxxx classes, with self.path and self.props the appropriate consul key structure"""

    @property
    def node(self):
        return str(concon.agent.self()['Member']['Name'])

    def _isfolder(self):
        return self.path[-1] == '/'

    def get(self, key=""):
        if key != "":
            key = '/' + key
        if 'props' in vars(self):
            result = {}
            for p in self.props:
                r = concon.kv.get(self.path + key + '/' + p)[1]
                if isinstance(r, dict):
                    r = r['Value'].decode('utf-8')
                if r is not None:
                    result.update({p: r})
            if result == {}:
                return None
            else:
                return result
        else:
            result = concon.kv.get(self.path + key)[1]
            if isinstance(result, dict) and 'Value' in result:
                if isinstance(result['Value'], bytes):
                    return result['Value'].decode('utf-8')
                else:
                    return result['Value']
            else:
                return result

    def load(self):
        if 'props' in vars(self):
            for p in self.props:
                r = concon.kv.get(self.path + '/' + p)[1]
                if isinstance(r, dict):
                    r = r['Value']
                    if r is None:
                        r = ""
                    else:
                        r = r.decode('utf-8')
                else:
                    r = ""
                self.__setattr__(p, r)
        else:
            result = concon.kv.get(self.path + '/' + self.key)[1]
            if isinstance(result, dict) and 'Value' in result:
                self.__setattr__('content', result)

    def exists(self, key=""):
        if key != "" and not self._isfolder():
            key = '/' + key
        result = concon.kv.get(self.path + key)[1]
        if isinstance(result, dict):
            if 'Key' in result:
                return True
            else:
                return False
        if result is None:
            if concon.kv.get(self.path + key, keys=True)[1] is None:
                return False
            else:
                return True
        return False

    def list(self, key=""):
        if self._isfolder():
            result = []
            objlist = concon.kv.get(self.path + key, keys=True)[1]
            if not isinstance(objlist, list):
                return []
            if self.path in objlist:
                objlist.remove(self.path)
            for i in objlist:
                name = i.replace(self.path, "").split('/')[0]
                if name not in result:
                    result.append(name)
            return result
        else:
            return list(self.dict(key))

    def is_empty(self, key=""):
        if not self.exists():
            return True
        if not self.list(key=key):
            return True
        return False

    def dict(self, key=""):
        if self._isfolder():
            result = {}
            for k in self.value:
                result.update(k.dict())
            return result
        else:
            result = {'key': self.key}
            if 'props' in vars(self):
                for p in self.props:
                    result.update({p: vars(self)[p]})
                return result
            else:
                return {self.key: self.get(key)}

    def save(self):
        """ can take props dict or simple value into props[0] when only one props"""
        if 'props' in vars(self):
            for p in self.props:
                concon.kv.put(self.path + '/' + p, vars(self)[p])
        else:
            concon.kv.put(self.path, self.value)
        return self

    def add(self, key, value=""):
        """ can take props dict or simple value into props[0] when only one props"""
        if self.exists(key):
            return False
        if 'props' in vars(self):
            if len(self.props) > 1:
                for p in self.props:
                    if p in value:
                        concon.kv.put(self.path + key + '/' + p, str(value[p]))
            else:
                concon.kv.put(self.path + key + '/' + self.props[0], str(value))
        else:
            concon.kv.put(self.path + key, value)
        self.load()
        return True

    def update(self, value):
        """ can take props dict or simple value into props[0] when only one props"""
        if 'props' in vars(self):
            for p in self.props:
                if p in value:
                    if isinstance(value[p], list):
                        vars(self)[p] = str('\n'.join(value[p]))
                    else:
                        vars(self)[p] = value[p]
                    concon.kv.put(self.path + '/' + p, vars(self)[p])
            return self
        else:
            if concon.kv.put(self.path, value):
                return self
            else:
                return None

    def delete(self, key="", recurse=False):
        if key != "" and not self._isfolder():
            key = '/' + key
        if not self.exists(key):
            return False
        if 'props' in vars(self) or key != "":
            recurse = True
        return concon.kv.delete(self.path + key, recurse=recurse)


class DataBase(ConsulDataMixin, object):
    def __init__(self):
        self.base = 'haproxy'

    @property
    def key(self):
        return self.base

    def getPath(self):
        return self.base + '/'

    @property
    def path(self):
        return self.getPath()


class DataFolders(DataBase):
    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self.folders = dict(
            cast='casting',
            publ='running',
            prev='tailing',
            pend='pending',
            test='testing',
            fail='failing',
        )

    @property
    def key(self):
        return self.folder

    @property
    def value(self):
        return self.folders

    def __repr__(self):
        return self.folders[self.folder]

    def getPath(self):
        if self.folder in self.folders:
            return super().getPath() + self.folders[self.folder] + '/'
        else:
            return super().getPath() + self.folder + '/'


class DataCasting(DataFolders):
    def __init__(self, cast):
        super().__init__('cast')
        self.cast = cast
        self.casting = dict(
            acct='accounts',
            fqdn='fqdns',
            cert='certs',
            conf='config'
        )
        self.states = dict(
            publish='publish',
            published='publish',
            publish_failed='publish',
            unpublish='unpublish',
            unpublished='unpublish'
        )

    @property
    def key(self):
        return self.cast

    @property
    def value(self):
        return self.casting

    def getPath(self):
        if self.cast in self.casting:
            return super().getPath() + self.casting[self.cast] + '/'
        else:
            return super().getPath() + self.cast + '/'


class DataStages(DataFolders):

    def __init__(self, stage):
        super().__init__(stage)
        self.stage = stage
        self.stages = self.folders
        # cast is not a datastage
        self.stages.pop('cast')

    @property
    def key(self):
        return self.stage

    @property
    def value(self):
        return self.stages

    def getPath(self):
        return super().getPath()


class DataEndpoints(ConsulDataMixin, object):

    def __init__(self, stage, bonnet, mode=None, spiid=None):
        super().__init__()
        self.stage = DataStages(stage)
        self.spiid = spiid
        self.bonnet = bonnet
        self.mode = mode
        self.endpoints = dict(
            status='status',
            certs='certs',
            front=dict(
                tcp="frontends-tcp",
                http="frontends-http"),
            frontex=dict(
                tcp="frontends-tcp-extended",
                http="frontends-http-extended"),
            back=dict(
                tcp="backends-tcp",
                http="backends-http")
        )
        self.modes = ['http', 'tcp']
        self.endpoint = ""
        if self.mode is None and (self.bonnet == 'certs' or self.bonnet == 'status'):
            self.endpoint = self.endpoints[self.bonnet]
        elif self.bonnet in self.endpoints.keys() and self.mode in self.endpoints[self.bonnet]:
            self.endpoint = self.endpoints[self.bonnet][self.mode]
        else:
            self.endpoint = self.bonnet + str(self.mode)

    @property
    def key(self):
        return self.stage.key

    @property
    def value(self):
        return self.endpoint

    def getPath(self):
        if self.spiid:
            return "{}{}/{}/".format(self.stage.getPath(), self.spiid, self.endpoint)
        else:
            if self.endpoint == "":
                return self.stage.getPath()
            else:
                return self.stage.getPath() + self.endpoint + '/'

    @property
    def path(self):
        return self.getPath()


class Accounts(DataCasting, object):
    def __init__(self, admin="", password=""):
        super().__init__('acct')
        self.accounts = []
        for u in self.list():
            self.accounts.append(Account(u))
        if not self.accounts:
            logging.info("Initial configuration {} {}".format(admin, password))
            self.add(admin)
            Account(admin).change(password)

    @property
    def key(self):
        return self.cast

    @property
    def value(self):
        return self.accounts

    def __repr__(self):
        return str(self.accounts)

    def __len__(self):
        return len(self.accounts)

    def __iter__(self):
        self.iter = 0
        return self

    def __next__(self):
        if self.iter < len(self.accounts):
            self.iter = self.iter + 1
            return str(self.accounts[self.iter - 1])
        raise StopIteration()

    # noinspection PyBroadException
    def load_yaml(self, file):
        try:
            with open(file, 'r') as f:
                acct_list = yaml.load(f, Loader=yaml.SafeLoader)
                f.close()
        except Exception:
            acct_list = {}
        for acct in acct_list:
            password = acct_list[acct]
            self.add(acct)
            Account(acct).update(password)
        return self.list()

    def dict(self, **kwargs):
        result = []
        d = super().dict()
        for i in d:
            result.append({'login': i, 'password': d[i]})
        return result


class Account(DataCasting, object):
    def __init__(self, login=None):
        super().__init__('acct')
        self.login = login
        if login is not None:
            self.password = self.get()

    @property
    def key(self):
        return self.login

    @property
    def value(self):
        return self.password

    @classmethod
    def create(cls, payload):
        result = cls(payload['login'])
        result.save()
        result.change(payload['password'])
        return result

    def json(self):
        return {'login': self.login, 'password': self.password}

    def __repr__(self):
        return self.login

    def getPath(self):
        return super().getPath() + self.login

    def change(self, password):
        if not self.exists():
            return False
        self.password = self.hashpass(password)
        super().save()
        return self

    def check(self, password):
        return self.hashcheck(self.password, password)

    @staticmethod
    def hashpass(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def hashcheck(hashed, password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


class Fqdns(DataCasting, object):
    def __init__(self):
        super().__init__('fqdn')
        self.fqdns = []
        for f in self.list():
            self.fqdns.append(Fqdn(f))

    @property
    def key(self):
        return self.cast

    @property
    def value(self):
        return self.fqdns

    def __repr__(self):
        return str(list(self.list()))

    def __iter__(self):
        self.iter = 0
        return self

    def __next__(self):
        if self.iter < len(self.fqdns):
            self.iter = self.iter + 1
            return str(self.fqdns[self.iter - 1])
        raise StopIteration()

    def add(self, fqdn, value=None):
        if value is None:
            value = {}
        value.update({'fqdn': fqdn})
        result = Fqdn.create(value)
        if result:
            return result
        return False

    # noinspection PyBroadException
    def load_yaml(self, file):
        try:
            with open(file, 'r') as f:
                fqdn_list = yaml.load(f, Loader=yaml.SafeLoader)
                f.close()
        except Exception:
            fqdn_list = {}
        logging.info(" load file content {}".format(str(fqdn_list)))
        for fqdn in fqdn_list:
            value = fqdn_list[fqdn]
            value['backend'] = '\n'.join(value['backend'])
            if self.exists(fqdn):
                Fqdn(fqdn).update(value)
            else:
                self.add(fqdn, value)
        return fqdn_list

    def json(self, owner=None):
        results = []
        for fqdn in super().list():
            if Fqdn(fqdn).owner == owner or owner is None:
                results.append(Fqdn(fqdn).json())
        return results

    def publish(self, owner=None):
        results = []
        for fqdn in super().list():
            if Fqdn(fqdn).owner == owner or owner is None:
                if Fqdn(fqdn).publish():
                    results.append(Fqdn(fqdn).json())
        logging.info(str(results))
        return results

    def unpublish(self, owner=None):
        results = []
        for fqdn in super().list():
            if Fqdn(fqdn).owner == owner or owner is None:
                if Fqdn(fqdn).unpublish():
                    results.append(Fqdn(fqdn).json())
        logging.info(str(results))
        return results


class Fqdn(DataCasting, object):
    def __init__(self, fqdn=None):
        super().__init__('fqdn')
        self.fqdn = fqdn
        self.props = list(DataModel['haproxy']['casting']['fqdns']['fqdn'])
        self.props.remove('fqdn')
        if fqdn is not None:
            self.load()

    @property
    def key(self):
        return self.fqdn

    @property
    def value(self):
        return self.dict()

    @property
    def backend_name(self):
        return self.fqdn + '-' + self.owner

    @property
    def front_type(self):
        if self.extended == "true":
            return "frontex"
        else:
            return "front"

    @property
    def frontend_content(self):
        if self.extended == "true":
            self.frontex = ""
            if self.mode == "tcp":
                self.frontex = "use_backend {backend}-tcp if {{ req_ssl_sni -i {subdom} {fqdn} }}"
            if self.mode == "http":
                self.frontex = "acl {backend} hdr_end(host) -i {subdom} {fqdn}\n"
                self.frontex += "use_backend {backend}-http if {backend}"

            if self.buggyclient == "true":
                if self.mode == "tcp":
                    self.frontex += "\nuse_backend {backend}-tcp if {{ req_ssl_sni -i {subdom} {fqdn}:443 }}"
                if self.mode == "http":
                    self.frontex += "\nacl {backend}-buggyclient hdr_end(host) -i {subdom} {fqdn}:443\n"
                    self.frontex += "use_backend {backend}-http if {backend}-buggyclient"
            subdomainoption = ""
            if self.subdomains == "true":
                subdomainoption = "-m end"
            return self.frontex.format(subdom=subdomainoption, backend=self.backend_name, fqdn=self.fqdn)
        else:
            return self.backend_name

    def exists(self, key=""):
        """ check if an fqdn of any mode exists """
        mode = self.mode
        self.mode = 'tcp'
        if super().exists():
            self.mode = mode
            return True
        self.mode = 'http'
        if super().exists():
            self.mode = mode
            return True
        return False

    @classmethod
    def create(cls, payload):
        result = cls(payload['fqdn'])
        if 'subdomains' in payload and payload['subdomains'] == "true":
            result.extended = "true"
        if 'buggyclient' in payload and payload['buggyclient'] == "true":
            result.extended = "true"
        result.update(payload)
        result.save()
        return result

    def update(self, value):
        super().update(value)
        self.save()
        if self.is_publish():
            self.publish()
        return self

    @staticmethod
    def timestamp():
        return datetime.datetime.now().timestamp()

    # noinspection PyBroadException
    @staticmethod
    def timeout(timepoint, delta=10):
        if datetime.datetime.now().timestamp() > (timepoint + delta):
            return True
        return False

    def spiidgen(self):
        maxwaittime = 10
        maxstucktime = 5 * 60

        now = self.timestamp()

        # while something is tested
        while not Endpoint('test', '', '', '').is_empty() and not self.timeout(now, maxwaittime):
            logging.warning(" hoho, it's not empty : {}".format(str(round(self.timestamp() - now, 2))))
            time.sleep(0.3)

        # some entries are stuck ! so clean it
        if not Endpoint('test', '', '', '').is_empty():
            logging.warning(" hoho, it wasn't empty")
            for test in Endpoint('test', '', '', '').list():
                if now - float(test.split('-')[-1]) > maxstucktime:
                    logging.warning(" hoho, something is stuck :{}".format(test))
                    Endpoint('test', test, '', '').delete(recurse=True)

        self.spiid = "{}-{}".format(self.backend_name, str(self.timestamp()))
        return self.spiid

    def safe(self):
        self.message = ""
        if self.state not in self.states:
            logging.info(' bad state {} for {}'.format(self.state, self.key))
            self.message = "state: {} unknown; cleaned to 'unpublish'.\n".format(self.state)
            self.state = "unpublish"
            self.save()
        if self.mode not in ['http', 'tcp']:
            logging.info(' bad mode {} for {}'.format(self.mode, self.key))
            self.message = self.message + "mode: {} unknown; cleaned to 'http'.\n".format(self.mode)
            self.mode = "http"
            self.save()
        return self

    def __repr__(self):
        return self.fqdn

    def getPath(self):
        return super().getPath() + self.fqdn

    def json(self):
        result = self.dict()
        logging.info(' self.dict : {}'.format(str(result)))
        result['fqdn'] = result.pop('key')
        result['backend'] = result['backend'].split('\n')
        if result['message'] == "":
            result['message'] = []
        else:
            result['message'] = result['message'].split('\n')
        return result

    def destroy(self):
        f = self
        if not self.is_unpublish():
            self.unpublish()
        if self.delete():
            f.state = "deleted"
            return f
        f.state = "not_deleted"
        return f

    def is_publish(self):
        return self.states[self.state] == 'publish'

    def is_publish_fail(self):
        return self.state == 'publish_failed'

    def is_unpublish(self):
        return self.states[self.state] == 'unpublish'

    def unpublish(self):
        if self.is_unpublish():
            return self
        if (not Endpoint('publ', self.front_type, self.mode, self.fqdn).exists() and
                not Endpoint('publ', 'back', self.mode, self.backend_name).exists()):
            self.state = 'unpublish'
            return self
        Endpoint('publ', self.front_type, self.mode, self.fqdn).delete()
        Endpoint('publ', 'back', self.mode, self.backend_name).delete()
        if not Endpoint('publ', self.front_type, self.mode, self.fqdn).exists():
            self.state = 'unpublish'
        self.save()
        return self

    @property
    def testpoint_backend(self):
        return Endpoint('test', 'back', self.mode, self.backend_name, spiid=self.spiid)

    @property
    def testpoint_frontend(self):
        return Endpoint('test', self.front_type, self.mode, self.fqdn, spiid=self.spiid)

    @property
    def failpoint_backend(self):
        return Endpoint('fail', 'back', self.mode, self.backend_name, spiid=self.spiid)

    @property
    def failpoint_frontend(self):
        return Endpoint('fail', self.front_type, self.mode, self.fqdn, spiid=self.spiid)

    @property
    def publpoint_backend(self):
        return Endpoint('publ', 'back', self.mode, self.backend_name)

    @property
    def publpoint_frontend(self):
        return Endpoint('publ', self.front_type, self.mode, self.fqdn)

    def publish(self):
        logging.info(' fqdn publish start')
        # made @ update method
        # if self.is_publish():
        #    self.unpublish()

        self.spiidgen()
        logging.info(str(self.dict()))
        # push backend first
        # cleanup failing
        if self.failpoint_backend.exists():
            self.failpoint_backend.delete(recurse=True)
            logging.info(' rapixy publish : delete logfail backend {}'.format(self.backend_name))

        logging.info(' rapixy publish : test push backend {}'.format(self.backend_name))
        self.testpoint_backend.update(self.backend)

        validate = ConsulTemplate(self.spiid)

        if not validate.evaluation():
            self.testpoint_backend.delete()
            self.message = validate.returnerr
            self.failpoint_backend.update(validate.returnerr)
            logging.info(" fail publish backend {} : {}".format(self.backend_name, self.message))
            self.state = "publish_failed"
            self.save()
            return self

        # push then frontend
        # cleanup failing
        if self.failpoint_frontend.exists():
            self.failpoint_frontend.delete(recurse=True)
            logging.info(' rapixy publish : delete logfail frontend {}'.format(self.backend_name))

        logging.info(' rapixy publish : test push frontend {}'.format(self.backend_name))
        self.testpoint_frontend.update(self.frontend_content)

        validate = ConsulTemplate(self.spiid)

        if not validate.evaluation():
            self.testpoint_frontend.delete()
            self.message = validate.returnerr
            self.failpoint_frontend.update(validate.returnerr)
            logging.info(" fail publish backend {} : {}".format(self.backend_name, self.message))
            self.state = "publish_failed"
            self.save()
            return self

        self.testpoint_backend.delete()
        self.testpoint_frontend.delete()
        self.publpoint_backend.update(self.backend)
        self.publpoint_frontend.update(self.frontend_content)
        self.message = ""
        self.state = "published"
        self.save()
        return self


class Certs(DataCasting, object):
    def __init__(self):
        super().__init__('cert')
        self.certs = []
        for c in self.list():
            self.certs.append(Cert(c))

    @property
    def key(self):
        return self.cast

    @property
    def value(self):
        return self.certs

    def __repr__(self):
        return str(list(self.list()))

    def __iter__(self):
        self.iter = 0
        return self

    def __next__(self):
        if self.iter < len(self.certs):
            self.iter = self.iter + 1
            return str(self.certs[self.iter - 1])
        raise StopIteration()

    @staticmethod
    def get_cert_cn(cert):
        cn = ""
        x = x509.load_pem_x509_certificate(cert.encode('ascii'), default_backend())
        for i in x.subject.rfc4514_string().split(','):
            if 'CN=' in i:
                cn = i.split('=')[1]
        return cn

    def load_file(self, root, filename):
        try:
            with open(root + '/' + filename, 'r') as f:
                cert_content = f.read()
                f.close()
            cn = self.get_cert_cn(cert_content)
        except Exception as err:
            return False, str(err)
        return cn, cert_content

    def load_content(self, content):
        try:
            cn = self.get_cert_cn(content)
        except Exception as err:
            return False, str(err)
        return True, cn

    def load_dir(self, basedir):
        result = {}
        for root, dirs, files in os.walk(basedir):
            if "/" not in root:
                continue
            owner = root.split('/')[-1]
            for filename in files:
                if filename[-4:] != '.pem':
                    result.update({filename: {
                        "status": "not_imported",
                        "info": "Can't import {} without .pem extension".format(filename),
                        "name": None,
                        "cn": None,
                        "owner": None}})
                    continue
                cn, cert_content = self.load_file(root, filename)
                if not cn:
                    result.update({filename: {
                        "status": "not_imported",
                        "info": 'Import {} error: {}'.format(filename, cert_content),
                        "name": None,
                        "cn": None,
                        "owner": None}})
                else:
                    cert_name = filename[:-4]
                    Cert(cert_name).update({"owner": owner, "content": cert_content,
                                            "state": 'publish', "fqdn": cn})
                    result.update({filename: {
                        "status": "imported",
                        "info": 'imported as {} for cn = {}'.format(cert_name, cn),
                        "name": cert_name,
                        "cn": cn,
                        "owner": owner}})
        return result

    def json(self, owner=None):
        results = []
        for cert in super().list():
            if Cert(cert).owner == owner or owner is None:
                results.append(Cert(cert).json())
        return results

    def publish(self, owner=None):
        results = []
        for cert in super().list():
            if Cert(cert).owner == owner or owner is None:
                if Cert(cert).publish():
                    results.append(Cert(cert).json())
        return results


class Cert(DataCasting, object):
    def __init__(self, cert):
        super().__init__('cert')
        self.cert = cert
        self.props = list(DataModel['haproxy']['casting']['certs']['cert'])
        self.props.remove('cert')
        self.load()

    @property
    def key(self):
        return self.cert

    @property
    def value(self):
        return self.dict()

    def __repr__(self):
        return self.cert

    def getPath(self):
        return super().getPath() + self.cert

    def json(self):
        result = self.dict()
        result['cert'] = result.pop('key')
        result['content'] = result['content'].split('\n')
        if result['message'] == "":
            result['message'] = []
        else:
            result['message'] = result['message'].split('\n')
        return result

    def is_publish(self):
        return self.states[self.state] == 'publish'

    def is_unpublish(self):
        return self.states[self.state] == 'unpublish'

    def unpublish(self):
        self.message = ""
        if self.is_unpublish():
            return self
        cert_name = self.cert + "-" + self.owner
        if not Endpoint('publ', 'certs', None, cert_name).exists():
            self.state = 'unpublished'
            return self
        Endpoint('publ', 'certs', None, cert_name).delete()
        if not Endpoint('publ', 'certs', None, cert_name).exists():
            self.state = 'unpublished'
        self.save()
        return self

        return False

    @staticmethod
    def timestamp():
        return datetime.datetime.now().timestamp()

    # noinspection PyBroadException
    @staticmethod
    def timeout(timepoint, delta=10):
        if datetime.datetime.now().timestamp() > (timepoint + delta):
            return True
        return False

    def spiidgen(self):
        maxwaittime = 10
        maxstucktime = 5 * 60

        now = self.timestamp()

        # while something is tested
        while not Endpoint('test', '', '', '').is_empty() and not self.timeout(now, maxwaittime):
            logging.warning(" hoho, it's not empty : {}".format(str(round(self.timestamp() - now, 2))))
            time.sleep(0.3)

        # some entries are stuck ! so clean it
        if not Endpoint('test', '', '', '').is_empty():
            logging.warning(" hoho, it wasn't empty")
            for test in Endpoint('test', '', '', '').list():
                if now - float(test.split('-')[-1]) > maxstucktime:
                    logging.warning(" hoho, something is stuck :{}".format(test))
                    Endpoint('test', test, '', '').delete(recurse=True)

        self.spiid = "{}-{}".format(self.certname, str(self.timestamp()))
        return self.spiid

    @property
    def certname(self):
        return self.cert + "-" + self.owner

    @property
    def testpoint_cert(self):
        return Endpoint('test', 'certs', None, self.certname, spiid=self.spiid)

    @property
    def failpoint_cert(self):
        return Endpoint('fail', 'certs', None, self.certname, spiid=self.spiid)

    @property
    def publpoint_cert(self):
        return Endpoint('publ', 'certs', None, self.certname)

    # noinspection PyBroadException
    def publish(self):
        logging.info(' cert publish start')
        if self.is_publish():
            self.unpublish()

        self.spiidgen()
        logging.info("cert {} : {}".format(self.key, self.fqdn))

        # cleanup first
        if self.failpoint_cert.exists():
            self.failpoint_cert.delete(recurse=True)

        # write certificates files to runningcertsdir
        testfile = "/etc/ssl/testing/" + self.certname + ".pem"
        try:
            with open(testfile, 'w') as f:
                f.write(self.content)
                f.close()
            logging.info('written certificate {}'.format(testfile))
        except Exception as e:
            logging.info("error writing certificate: {}".format(str(e)))

        # input('wtf?')
        # push cert to testing
        self.testpoint_cert.update(self.content)

        # check it
        validate = ConsulTemplate(self.spiid)
        evaluation = validate.evaluation()

        # cleanup testing folder and key
        self.testpoint_cert.delete()
        try:
            os.remove(testfile)
        except Exception:
            pass

        if not evaluation:
            self.message = validate.returnerr
            self.failpoint_cert.update(validate.returnerr)
            logging.info(" fail publish certificate {} : {}".format(self.certname, self.message))
            self.state = "publish_failed"
            self.save()
            return self

        # publish in running
        self.publpoint_cert.update(self.content)

        # cleanup
        self.message = ""
        self.state = "published"
        self.save()
        return self


class Config(DataCasting, object):
    def __init__(self, option=None):
        super().__init__('conf')
        self.option = option
        if option is not None:
            self.opt_content = self.get()

    @property
    def key(self):
        return self.option

    @property
    def value(self):
        return self.opt_content

    def json(self):
        return {'option': self.option, 'content': self.opt_content}

    def __repr__(self):
        return self.option

    def getPath(self):
        return super().getPath() + self.option

    # noinspection PyBroadException
    def load_file(self, root, filename):
        try:
            with open(root + '/' + filename, 'r') as f:
                self.opt_content = f.read()
                f.close()
        except Exception:
            return False
        self.save()
        return self.json()


class Endpoints(DataEndpoints, object):
    def __init__(self, stage, bonnet, mode=None):
        super().__init__(stage, bonnet, mode)

    def __repr__(self):
        return self.stage.__repr__() + '/' + self.endpoint


class Endpoint(DataEndpoints, object):
    """ stage in pending, testing, ...
    bonnet in frontends, backends, certs
    mode in tcp, http or None
    endp in key name"""

    def __init__(self, stage, bonnet, mode, endp, spiid=None):
        super().__init__(stage, bonnet, mode, spiid)
        self.endp = endp
        self.content = self.get(endp)

    @property
    def key(self):
        return self.key

    @property
    def value(self):
        return self.content

    @classmethod
    def create(cls, stage, bonnet, mode, endp, content):
        result = cls(stage, bonnet, mode, endp)
        result.update(content)
        return result

    def __repr__(self):
        return self.stage.__repr__() + '/' + self.endpoint + '/' + self.endp

    def getPath(self):
        return super().getPath() + self.endp


####
# api namespaces

####
# accounts
get_token = api.namespace('login', description='Login with tenant ID and Secret/Token to get an Authorization token',
                          ordered=True)
get_token_m = api.model('login', {
    'Authorization': fields.String(readOnly=True,
                                   description="Used in Header within Authorization field (clic the green Authorize)")})
get_token2 = api2.namespace('login', description='Login with tenant ID and Secret/Token to get an Authorization token',
                            ordered=True)
get_token2_m = api2.model('login', {
    'Authorization': fields.String(readOnly=True,
                                   description="Used in Header within Authorization field (clic the green Authorize)")})
tenant = api2.namespace('account', description='Rapixy account (reserved for Ops operations)', ordered=True)
tenant_m = api2.model('account', {
    'login': fields.String(readOnly=True, description='The tenant ID as an Rapixy account'),
    'password': fields.String(required=True, description='The Secret/Token as Rapixy account\'s password')
})

####
# Fqdns()
fqdn_ns = api.namespace('fqdn', description='Fully Qualified Domain Name', ordered=True)
fqdn_m = api.model('fqdn_request', {
    'fqdn': fields.String(required=True, description='FQDN frontend response', example='myapp.vpod.carrefour.com'),
    'state': fields.String(required=False, description='authorized values : ' + ' or '.join(DataCasting("").states),
                           default=DataCasting("").states['publish'], example=DataCasting("").states['publish']),
    'mode': fields.String(
        description='authorized values : ' + ' or '.join(DataEndpoints("", "").modes) + ' (passthrough)',
        required=False,
        default=DataEndpoints("", "").modes[0], example=DataEndpoints("", "").modes[0]),
    'subdomains': fields.String(
        description='authorized values : true or false. Redirect any subdomain when true',
        required=False,
        default="false", example="false"),
    'buggyclient': fields.String(
        description='authorized values : true or false. defines also a "fqdn:443". Seriously.',
        required=False,
        default="false", example="false"),
    'backend': fields.List(fields.String(required=False, description='Code for haproxy in backend section.'),
                           example=["balance roundrobin", "option ssl-hello-chk",
                                    "server srv01 10.0.0.10:443 weight 1 maxconn 100 check",
                                    "server srv02 10.0.0.11:443 weight 1 maxconn 100 check"]),
})
fqdn_mr = api.inherit('fqdn_response', fqdn_m, {
    'message': fields.List(fields.String(
        description='messages from validation test (empty string when all is good)', default="''")),
    'spiid': fields.String(
        description='SuPport Information IDentifier. Give it to support call.')
})

####
# publisher
pub_ns = api.namespace('publish', description='publish and unpublish defined fqdn or certificate', ordered=True)

####
# certs
cert_ns = api.namespace('cert', description='Certificates manager', ordered=True)
cert_m = api.model('cert_request', {
    'cert': fields.String(required=True, description='FQDN frontend response', example='myapp.vpod.carrefour.com'),
    'state': fields.String(required=False, description='authorized values : ' + ' or '.join(DataCasting("").states),
                           default='publish', example='publish'),
    'fqdn': fields.String(required=True, description='associated fqdn'),
})

cert_mr = api.inherit('cert_response', cert_m, {
    'message': fields.List(fields.String(
        description='messages from validation test (empty string when all is good)', default="''")),
    'spiid': fields.String(
        description='SuPport Information IDentifier. Give it to support call.'),
    'content': fields.List(fields.String(), description='the jsonified content of the certificate')
})

upload_cert = cert_ns.parser()
upload_cert.add_argument('file', location='files',
                         type=FileStorage, required=True)
upload_cert.add_argument('name', required=True, help="The name of the certificate")

####
# adminops

ops_ns = api2.namespace('ops', description='Administrative operations', ordered=True)

upload_json = ops_ns.parser()
upload_json.add_argument('file', location='files',
                         type=FileStorage, required=True)

####
# api endpoints

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
            api.abort(401, "Bad credentials")
        if Account(name).check(password):
            access_token = create_access_token(identity=name)
            return jsonify(access_token=access_token)
        else:
            api.abort(401, "Bad credentials")


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
            api.abort(401, "Bad credentials")
        if Account(name).check(password):
            access_token = create_access_token(identity=name)
            return jsonify(access_token=access_token)
        else:
            api.abort(401, "Bad credentials")


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
            api.abort(401, "Bad account")
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
        return Account().create(api.payload).json(), 201


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
        return Account(account).change(api.payload['password'])


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
        api.payload.update({'owner': get_jwt_identity()})
        if Fqdn(api.payload['fqdn']).exists():
            fqdn_ns.abort(409, "Can't create already present 'fqdn' fqdn")
            return
        f = Fqdn().create(api.payload)
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
        f = Fqdn(fqdn).update(api.payload)
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
    from haprestio.operations import install

    if install.arguments.install is not None:
        install.install()

    if app.config['DEBUG']:
        app.run(debug=True, host=app.config['HOST'], port=app.config['PORT'])
    else:
        app.run(host=app.config['HOST'], port=app.config['PORT'])