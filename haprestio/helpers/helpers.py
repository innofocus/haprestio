import subprocess, consul, requests, csv, logging
from .. import app
from ..data.data import DataCasting


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
        nodes = consul.Consul(app.config['CONSUL_HOST'], app.config['CONSUL_PORT']).agent.agent.catalog.nodes()
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