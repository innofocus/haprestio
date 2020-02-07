#!/usr/bin/dumb-init /bin/sh
set -e

echo "Waiting for consul"
until /etc/haprestio/consul-template/helpers/consul_kv.py put waitingforconsul dumb-init 2> /dev/null; do sleep 1; printf ".";  done
/etc/haprestio/consul-template/helpers/consul_kv.py delete waitingforconsul

consul-template -config /etc/haprestio/consul-template/consul-template.cfg &

exec "$@"
