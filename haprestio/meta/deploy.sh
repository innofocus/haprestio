#!/usr/bin/env sh
basedir=$1

# haproxy
mkdir -p $basedir/../haproxy/conf.d
$basedir/templates/haproxy.cfg.py haproxyuser haproxypass > $basedir/../haproxy/haproxy.cfg
cp $basedir/certs/admin/* /etc/ssl/private
mkdir /etc/ssl/testing

# consul-template
chmod 755 $basedir/consul-template/helpers/*
