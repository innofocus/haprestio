#!/usr/bin/dumb-init /bin/sh
set -e

echo "Waiting for consul"
until /etc/haprestio/consul-template/helpers/consul_kv.py put testing dumb-init 2> /dev/null; do sleep 1; printf ".";  done
/etc/haprestio/consul-template/helpers/consul_kv.py delete testing
sleep 2

exec "$@"
