#!/usr/bin/env python3
import consul

c = consul.Consul(port="8501")

c.kv.delete('haproxy', recurse=True)
