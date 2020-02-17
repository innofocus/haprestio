#!/usr/bin/env python3
import multiprocessing, sys

haproxy_user = sys.argv[1]
haproxy_pass = sys.argv[2]

haproxy_cfg = """
global
  log stdout  format raw  local0  info
  #log /dev/log local0
  #log /dev/log local1 notice
  chroot /var/lib/haproxy
  stats socket /run/haproxy.admin.sock mode 660 level admin
  stats timeout 30s
  user haproxy
  group haproxy
  daemon
  maxconn 200000
  nbproc "{nbproc}"
  {cpumap}
  ca-base /etc/ssl/certs
  crt-base /etc/ssl/private
  ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS:!3DES
  ssl-default-bind-options no-sslv3
  tune.ssl.default-dh-param 2048

defaults
  default-server init-addr last,libc,none
  option log-health-checks
  mode    http
  option  dontlognull
  timeout connect 8000
  timeout client  60000s
  timeout server  60000s
  #errorfile 400 /etc/haproxy/errors/400.http
  #errorfile 403 /etc/haproxy/errors/403.http
  #errorfile 408 /etc/haproxy/errors/408.http
  #errorfile 500 /etc/haproxy/errors/500.http
  #errorfile 502 /etc/haproxy/errors/502.http
  #errorfile 503 /etc/haproxy/errors/503.http
  #errorfile 504 /etc/haproxy/errors/504.http

listen stats
  bind *:8282
  mode http
  bind-process {nbproc}
  stats enable
  stats uri /
  stats realm Haproxy\ Statistics
  stats show-desc "HAProxy WebStatistics"
  stats show-node
  stats show-legends
  stats auth {haproxy_user}:{haproxy_pass}
  stats admin if TRUE
"""
numcpu = multiprocessing.cpu_count()
cpumap="cpu-map 1 0\n"
for i in range(1,numcpu):
  cpumap += "  cpu-map {} {}".format(i+1,i)
  if i < numcpu-1:
    cpumap += "\n"

print(haproxy_cfg.format(nbproc=numcpu, cpumap=cpumap, haproxy_user=haproxy_user,
                         haproxy_pass=haproxy_pass))
