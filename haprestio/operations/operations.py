import os
import datetime
import subprocess
import json


class Operations(object):
    def __init__(self):
        self.import_cmd = "/usr/local/bin/consul kv import @{}"
        self.export_cmd = "/usr/local/bin/consul kv export haproxy"

    @staticmethod
    def timestamp():
        return "-".join(
            map(str, list(datetime.datetime.now().timetuple())[0:6] + [datetime.datetime.now().microsecond]))

    def import_file(self, file):
        ret = subprocess.run(self.import_cmd.format(file).split(),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if ret.returncode != 0:
            return {'success': False, 'message': ret.stderr.decode("utf-8")}
        return {'success': True, 'message': ret.stdout.decode('utf-8').splitlines()}

    def export_json(self):
        ret = subprocess.run(self.export_cmd.split(),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if ret.returncode != 0:
            return {'success': False, 'message': ret.stderr.decode("utf-8")}
        return json.loads(ret.stdout.decode('utf-8'))

    @staticmethod
    def get_hostname():
        system, node, release, version, machine = os.uname()
        return node

    def make_backup_name(self):
        return "{}-{}.json".format(self.get_hostname(), self.timestamp())

    def get_backup_date(self, backup_name):
        system, node, release, version, machine = os.uname()
        l = len(self.get_hostname())
        return backup_name[l + 1:l + 11]

    @staticmethod
    def jilt(node):
        return concon.kv.put("haproxy/jilting/{}".format(node), "Jilted!")

    def jilt_me(self):
        node = concon.agent.self()['Config']['NodeName']
        return self.jilt(node)

    def jilt_group(self):
        nodes = concon.agent.agent.catalog.nodes()
        retnodes = []
        ret = True
        for n in nodes[1]:
            ret *= self.jilt(n['Node'])
            if ret:
                retnodes.append(n['Node'])

        return {'jilted': retnodes}

    @staticmethod
    def unjilt(node):
        return concon.kv.delete("haproxy/jilting/{}".format(node))

    def unjilt_me(self):
        node = concon.agent.self()['Config']['NodeName']
        return self.unjilt(node)

    def unjilt_group(self):
        nodes = concon.agent.agent.catalog.nodes()
        retnodes = []
        ret = True
        for n in nodes[1]:
            ret *= self.unjilt(n['Node'])
            if ret:
                retnodes.append(n['Node'])
        return {'unjilted': retnodes}

    def get_jilt(self):
        nodes = concon.kv.get("haproxy/jilting", keys=True)
        ret = []
        if nodes[1]:
            for n in nodes[1]:
                ret.append(n.split('/')[-1])
        return {'jilted': ret}

    def maintenance_on(self):
        return concon.kv.put("haproxy/maintenance", "On!")

    def maintenance_off(self):
        return concon.kv.delete("haproxy/maintenance")
