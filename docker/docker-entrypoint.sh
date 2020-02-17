#!/usr/bin/dumb-init /bin/sh
set -e

echo "Startup file is waiting for consul"
until /etc/haprestio/consul-template/helpers/consul_kv.py put waitingforconsul dumb-init 2> /dev/null; do sleep 1; printf ".";  done
/etc/haprestio/consul-template/helpers/consul_kv.py delete waitingforconsul

# run consul template
consul-template -config /etc/haprestio/consul-template/consul-template.cfg &

# run haproxy
PIDFILE=/run/haproxy.pid
haproxy -D -p $PIDFILE -f /etc/haproxy -f /etc/haproxy/conf.d

export HAPRESTIO_CFG=/etc/haprestio/

exec "$@"