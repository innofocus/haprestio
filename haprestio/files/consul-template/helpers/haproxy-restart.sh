#!/usr/bin/env sh
here=$(dirname $0)
hacfg=$1
output="/run/haproxy.restart.out"
echo "$0 $(date)" > $output
haproxy -c -V -f /etc/haproxy/haproxy.cfg -f $hacfg  >> $output 2>&1
if [ $? -eq 0 ]; then
  $here/consul_kv.py put haproxy/status/$(hostname)/running/OK "$(cat $output)"
  $here/consul_kv.py delete haproxy/status/$(hostname)/running/ERROR
  systemctl status haproxy
  if [ $? -eq 0 ]; then
    systemctl reload haproxy
  else
    systemctl restart haproxy
  fi
  exit 0
else
  $here/consul_kv.py put haproxy/status/$(hostname)/running/ERROR "$(cat $output)"
  $here/consul_kv.py delete haproxy/status/$(hostname)/running/OK
  echo "test wasnt ok. haproxy remains unreloaded"
  exit 0
fi
