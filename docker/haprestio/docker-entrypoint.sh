#!/usr/bin/dumb-init /bin/sh
set -e

consul-template -config /etc/haprestio/consul-template/consul-template.cfg &

exec "$@"
