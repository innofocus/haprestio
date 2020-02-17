#!/usr/bin/env sh


here=$(dirname $0)
hacfg=$1
output="/run/haproxy.restart.out"
PIDFILE=/run/haproxy.pid

haproxy_status()
{
        if [ ! -f $PIDFILE ] ; then
                # program not running
                return 3
        fi

        for pid in $(cat $PIDFILE) ; do
                if ! cat /proc/$pid/cmdline | grep haproxy > /dev/null ; then
                        # program running, bogus pidfile
                        return 1
                fi
        done

        return 0
}



echo "$0 $(date)" > $output
haproxy -c -V -f /etc/haproxy/haproxy.cfg -f $hacfg  >> $output 2>&1

if [ $? -eq 0 ]; then
  $here/consul_kv.py put haproxy/status/$(hostname)/running/OK "$(cat $output)"
  $here/consul_kv.py delete haproxy/status/$(hostname)/running/ERROR
  haproxy_status
  if [ $? -eq 0 ]; then
    haproxy -D -p $PIDFILE -sf $(cat $PIDFILE) -f /etc/haproxy -f /etc/haproxy/conf.d
  else
    haproxy -D -p $PIDFILE -f /etc/haproxy -f /etc/haproxy/conf.d
  fi
  exit 0
else
  $here/consul_kv.py put haproxy/status/$(hostname)/running/ERROR "$(cat $output)"
  $here/consul_kv.py delete haproxy/status/$(hostname)/running/OK
  echo "test wasnt ok. haproxy remains unreloaded"
  exit 0
fi
