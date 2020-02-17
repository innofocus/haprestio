import consul
from .. import *

class ConsulDataMixin(object):
    """ Mixin for Consulxxx classes, with self.path and self.props the appropriate consul key structure"""

    conscon = consul.Consul(app.config['CONSUL_HOST'], app.config['CONSUL_PORT'])

    @property
    def node(self):
        return str(self.conscon.agent.self()['Member']['Name'])

    def _isfolder(self):
        return self.path[-1] == '/'

    def get(self, key=""):
        if key != "":
            key = '/' + key
        if 'props' in vars(self):
            result = {}
            for p in self.props:
                r = self.conscon.kv.get(self.path + key + '/' + p)[1]
                if isinstance(r, dict):
                    r = r['Value'].decode('utf-8')
                if r is not None:
                    result.update({p: r})
            if result == {}:
                return None
            else:
                return result
        else:
            result = self.conscon.kv.get(self.path + key)[1]
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
                r = self.conscon.kv.get(self.path + '/' + p)[1]
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
            result = self.conscon.kv.get(self.path + '/' + self.key)[1]
            if isinstance(result, dict) and 'Value' in result:
                self.__setattr__('content', result)

    def exists(self, key=""):
        if key != "" and not self._isfolder():
            key = '/' + key
        result = self.conscon.kv.get(self.path + key)[1]
        if isinstance(result, dict):
            if 'Key' in result:
                return True
            else:
                return False
        if result is None:
            if self.conscon.kv.get(self.path + key, keys=True)[1] is None:
                return False
            else:
                return True
        return False

    def list(self, key=""):
        if self._isfolder():
            result = []
            objlist = self.conscon.kv.get(self.path + key, keys=True)[1]
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
                self.conscon.kv.put(self.path + '/' + p, vars(self)[p])
        else:
            self.conscon.kv.put(self.path, self.value)
        return self

    def add(self, key, value=""):
        """ can take props dict or simple value into props[0] when only one props"""
        if self.exists(key):
            return False
        if 'props' in vars(self):
            if len(self.props) > 1:
                for p in self.props:
                    if p in value:
                        self.conscon.kv.put(self.path + key + '/' + p, str(value[p]))
            else:
                self.conscon.kv.put(self.path + key + '/' + self.props[0], str(value))
        else:
            self.conscon.kv.put(self.path + key, value)
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
                    self.conscon.kv.put(self.path + '/' + p, vars(self)[p])
            return self
        else:
            if self.conscon.kv.put(self.path, value):
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
        return self.conscon.kv.delete(self.path + key, recurse=recurse)


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
