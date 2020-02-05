import yaml, logging, datetime, time
from . import DataModel
from .data import *
from .endpoints import Endpoint
from ..helpers.helpers import ConsulTemplate


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
