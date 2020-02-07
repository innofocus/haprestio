#!/usr/bin/env  python3
import sys, json, os, subprocess
import consul
import hashlib
import logging

config_file = '/etc/haprestio/haprestio.cfg'
config = dict()
with open(config_file, 'rb') as cfgfile:
    exec(compile(cfgfile.read(), config_file,'exec'), config )

logging.basicConfig(filename='/var/log/haprestio-helpers.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%D %H:%M:%S',
                    level=logging.ERROR)
logger = logging.getLogger(os.path.basename(sys.argv[0]))
logger.setLevel(logging.DEBUG)

####
# settings
runningFolder = "haproxy/running/certs/"
runningCertDir = "/etc/ssl/private/"
supermariocert = "supermario.pem"
certlistfile = "/etc/haproxy/conf.d/certlist.txt"

haproxyrestart = "/etc/haprestio/consul-template/helpers/haproxy-restart.sh /etc/haproxy/conf.d/haproxy.cfg"

# generate cert list
certlist = []

concon = consul.Consul(config['CONSUL_HOST'], config['CONSUL_PORT'])


def getIndex(key):
    index, value = concon.kv.get(key)
    return index


def getKeys(key):
    index, value = concon.kv.get(key, keys=True)
    return value


def getValue(key):
    index, value = concon.kv.get(key)
    if value is None:
        return None
    return value['Value'].decode('utf-8')


def deleteKey(key):
    return concon.kv.delete(key)
if getKeys(runningFolder) is not None:
    for cert in getKeys(runningFolder):
        endkey = cert.split("/")[-1]
        value = getValue(cert)
        logger.debug('haproxy-certs.py : # {}.pem '.format(endkey))
        if value is None:
            logger.debug('...: {} value none'.format(cert))
            continue

        runningFile = runningCertDir + endkey + ".pem"
        try:
            with open(runningFile, 'w') as f:
                f.write(value)
            f.close()
            logger.debug('....written to {}'.format(runningFile))
        except Exception as e:
            logger.debug('....NOT written to {}'.format(runningFile))
        certlist.append(endkey + ".pem")

# remove unpublished certificates
for root, dirs, files in os.walk(runningCertDir):
    for filename in files:
        if filename not in certlist and filename != supermariocert:
            try:
                logger.debug('removing file {}'.format(runningCertDir + filename))
                os.remove(runningCertDir + filename)
            except:
                pass

with open(certlistfile, "w") as f:
    f.writelines('\n'.join(certlist))
    #f.writelines('\nsupermario.pem')
f.close()

# print hash md5 certificate in running
print("# certs hashes")
concerts = concon.kv.get('haproxy/running/certs', keys=True)[1]
if isinstance(concerts, list):
    for i in concerts :
        print("# {} : {}".format(os.path.basename(i),
                           hashlib.md5(getValue(i).encode('utf-8')).hexdigest()))
