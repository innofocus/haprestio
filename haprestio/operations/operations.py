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

    def backup_list(self):
        storage_client = storage.Client.from_service_account_json(app.config['GOOGLE_APPLICATION_CREDENTIALS'])
        blobs = storage_client.list_blobs(app.config['BACKUP_BUCKET'])
        return [b.name for b in blobs]

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

    def backup_apply_policy(self):
        # get bucket
        storage_client = storage.Client.from_service_account_json(app.config['GOOGLE_APPLICATION_CREDENTIALS'])
        try:
            bucket = storage_client.get_bucket(app.config['BACKUP_BUCKET'])
        except:
            api.abort(500, "Backup failed on bucket {}".format(app.config['BACKUP_BUCKET']))

        # construct a list of backups by days
        backup_list = self.backup_list()
        backup_list_by_day = {}
        for b in backup_list:
            d = self.get_backup_date(b)
            if d in backup_list_by_day:
                c = backup_list_by_day[d] + [b]
            else:
                c = [b]
            backup_list_by_day.update({d: c})

        # policies
        today = datetime.date.today()
        deleted = []

        # max days policy
        max_date = today - datetime.timedelta(int(app.config['MAX_BACKUP_DAYS']))
        if len(backup_list_by_day) > int(app.config['MAX_BACKUP_DAYS']):
            for b in backup_list_by_day.keys():
                bdate = datetime.date(*map(int, b.split('-')))
                if bdate < max_date:
                    for bfile in backup_list_by_day[b]:
                        deleted.append(bfile)
                        bucket.blob(bfile).delete()

        # max backup per day
        for b in backup_list_by_day.keys():
            nb_backups = 0
            for bfile in backup_list_by_day[b]:
                nb_backups += 1
                if nb_backups > int(app.config['MAX_BACKUP_PER_DAY']):
                    deleted.append(bfile)
                    bucket.blob(bfile).delete()
        return deleted

    def backup_json(self):
        storage_client = storage.Client.from_service_account_json(app.config['GOOGLE_APPLICATION_CREDENTIALS'])
        try:
            bucket = storage_client.get_bucket(app.config['BACKUP_BUCKET'])
        except:
            api.abort(500, "Backup failed on bucket {}".format(app.config['BACKUP_BUCKET']))
        destination_blob_name = self.make_backup_name()
        blob = bucket.blob(destination_blob_name)

        ret = subprocess.run(self.export_cmd.split(),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if ret.returncode != 0:
            return {'success': False, 'message': ret.stderr.decode("utf-8")}
        try:
            blob.upload_from_string(ret.stdout.decode('utf-8'))
            policies = self.backup_apply_policy()
            return {"status": "success",
                    "backup_name": destination_blob_name,
                    "deleted_by_policies": policies}, 201
        except:
            api.abort(500, "Backup failed on bucket {}".format(app.config['BACKUP_BUCKET']))

    def restore_json(self, backupname):
        storage_client = storage.Client.from_service_account_json(app.config['GOOGLE_APPLICATION_CREDENTIALS'])
        try:
            bucket = storage_client.get_bucket(app.config['BACKUP_BUCKET'])
        except:
            api.abort(500, "Restore failed from blob {}:{}".format(app.config['BACKUP_BUCKET'], backupname))
        try:
            content = bucket.blob(backupname)
            content.download_to_filename("/tmp/{}".format(backupname))
            return self.import_file("/tmp/{}".format(backupname))
        except:
            api.abort(500, "Restore failed from blob {}:{}".format(app.config['BACKUP_BUCKET'], backupname))

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
