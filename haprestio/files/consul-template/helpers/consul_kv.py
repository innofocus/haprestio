#!/usr/bin/env python3
import consul, sys

config_file = '/etc/haprestio/haprestio.cfg'
config = dict()
with open(config_file, 'rb') as cfgfile:
    exec(compile(cfgfile.read(), config_file,'exec'), config )

concon = consul.Consul(config['CONSUL_HOST'], config['CONSUL_PORT'])

if sys.argv[1] == "put":
    concon.kv.put(sys.argv[2], sys.argv[3])
elif sys.argv[1] == "delete":
    concon.kv.delete(sys.argv[2])

