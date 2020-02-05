import os, datetime, time, logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .data import *
from . import DataModel
from .endpoints import Endpoint
from ..helpers.helpers import  ConsulTemplate

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
