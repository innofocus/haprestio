#!/usr/bin/env  python3
# this script get the generated configuration file for keys in testing
import sys, json, time, subprocess, os
import consul
import datetime
import logging

config_file = '/etc/haprestio/haprestio.cfg'
config = dict()
with open(config_file, 'rb') as cfgfile:
    exec(compile(cfgfile.read(), config_file,'exec'), config )
if 'CONSUL_HOST' not in config:
    config['CONSUL_HOST'] = "localhost"
if 'CONSUL_PORT' not in config:
    config['CONSUL_PORT'] = "8500"

logging.basicConfig(filename='/var/log/haprestio-helpers.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%D %H:%M:%S',
                    level=logging.ERROR)
logger = logging.getLogger(os.path.basename(sys.argv[0]))
logger.setLevel(logging.DEBUG)
logger.info('{} '.format(sys.argv[1]))

haproxycfg = sys.argv[1]
haproxycmd = "/usr/sbin/haproxy -c -V -f /etc/haproxy/haproxy.cfg -f {}".format(haproxycfg)


####
# data instance
concon = consul.Consul(config['CONSUL_HOST'], config['CONSUL_PORT'])
nodename = str(concon.agent.self()['Member']['Name'])

####
# settings
testingFolder = "haproxy/testing/" + nodename + '/'
failingFolder = "haproxy/failing/" + nodename + '/'
testingFlag = testingFolder + "status/Busy"
runningFolder = "haproxy/running/"
testingCertDir = "/etc/ssl/testing/"
runningCertDir = "/etc/ssl/private/"


order = ["backends-tcp","backends-http","frontends-tcp","frontends-http","certs"]
def getIndex (key):
  index, value = concon.kv.get(key)
  return index
def getKeys (key):
  index, value = concon.kv.get(key, keys=True)
  return value
def getValue (key):
  index, value = concon.kv.get(key)
  if value is None:
    return None
  return value['Value'].decode('utf-8')
def deleteKey (key):
  return concon.kv.delete(key)


# lauch haproxy in test mode
validate = subprocess.run(haproxycmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# if ok, then move keys to running, else to trash
keys = getKeys(testingFolder)
logger.debug('keys: {}\n'.format(str(keys)))

# if there is no key to test, then flag it's ok to receive tests
if not isinstance(keys, list):
  logger.debug('no key to test, then remove flag busy')
  deleteKey(testingFlag)
  exit(0)

#ok there are keys to test, put busy flag
concon.kv.put(testingFlag,str(datetime.datetime.now().timestamp()))

# remove testinFolder and testingFlag from list
if testingFolder in keys:
  keys.remove(testingFolder)

if testingFlag in keys:
  keys.remove(testingFlag)

if keys == []:
  logger.debug('nothing left to do\n')
  exit(0)

logger.debug('begin testing keys : {}\n'.format(str(keys)))

for folder in order:
  for testingSource in keys:
    if testingFolder + folder in testingSource:
      endkey = testingSource.split("/")[-1]
      value = getValue(testingSource)
      folder = testingSource.split("/")[-2]
      runningDest = testingSource.replace(testingFolder, runningFolder)
      trashDest = testingSource.replace(testingFolder, failingFolder)

      logger.debug("evaluate {}".format(endkey))
      deleteKey(testingSource)
      if validate.returncode == 0:
        logger.debug("success for {}".format(endkey))
        concon.kv.put(runningDest,value)

      else:
        # move to trash
        logger.debug("badluck for {}".format(endkey))
        logger.debug(" error: {}".format(validate.stderr.decode("utf-8")))
        if folder == "certs":
          sourceFile = testingCertDir + endkey + ".pem"
          try:
            os.remove(sourceFile)
          except:
            pass
        concon.kv.put(trashDest+"/content",value)
        concon.kv.put(trashDest+"/stdout",validate.stdout.decode("utf-8"))
        concon.kv.put(trashDest+"/stderr",validate.stderr.decode("utf-8"))
        concon.kv.put(trashDest+"/returncode",str(validate.returncode))

