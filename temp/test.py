#!/bin/env python3
import json
a = """{
  "myapp.vpod.that.com-string": [
    {
      "node": "vg1r7np-ci-rpxy-a-z1-01",
      "data": [
        {
          "stats": {
            "check_status": "L4TOUT",
            "downtime": "5425",
            "last_chk": "",
            "lastchg": "5425",
            "addr": "10.0.0.10:443",
            "check_code": "",
            "check_desc": "Layer4 timeout",
            "status": "up"
          },
          "svname": "srv01"
        },
        {
          "stats": {
            "check_status": "L4TOUT",
            "downtime": "5424",
            "last_chk": "",
            "lastchg": "5424",
            "addr": "10.0.0.11:443",
            "check_code": "",
            "check_desc": "Layer4 timeout",
            "status": "DOWN"
          },
          "svname": "srv02"
        },
        {
          "stats": {
            "check_status": "",
            "downtime": "5424",
            "last_chk": "",
            "lastchg": "5424",
            "addr": "",
            "check_code": "",
            "check_desc": "",
            "status": "DOWN"
          },
          "svname": "BACKEND"
        }
      ]
    },
    {
      "node": "vg1r7np-ci-rpxy-a-z2-01",
      "data": [
        {
          "stats": {
            "check_status": "L4TOUT",
            "downtime": "5424",
            "last_chk": "",
            "lastchg": "5424",
            "addr": "10.0.0.10:443",
            "check_code": "",
            "check_desc": "Layer4 timeout",
            "status": "DOWN"
          },
          "svname": "srv01"
        },
        {
          "stats": {
            "check_status": "L4TOUT",
            "downtime": "5424",
            "last_chk": "",
            "lastchg": "5424",
            "addr": "10.0.0.11:443",
            "check_code": "",
            "check_desc": "Layer4 timeout",
            "status": "DOWN"
          },
          "svname": "srv02"
        },
        {
          "stats": {
            "check_status": "",
            "downtime": "5424",
            "last_chk": "",
            "lastchg": "5424",
            "addr": "",
            "check_code": "",
            "check_desc": "",
            "status": "DOWN"
          },
          "svname": "BACKEND"
        }
      ]
    }
  ]
}"""
b=json.loads(a)
c=b['myapp.vpod.that.com-string']
ret={}
for s in c:
    for i in s:
        if i == "data":
            for d in s[i]:
                t = ""
                if d['svname'] in ret:
                    t = ret[d['svname']]
                nstatus = "/"+d['stats']['status']+"("+d['stats']['check_desc']+")"
                if t != nstatus:
                    ret.update({d['svname']: t+nstatus})

print(ret)


