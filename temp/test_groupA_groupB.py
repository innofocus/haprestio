#!/usr/bin/python3

verbose = False

urls={
"vg1r7np-ci": "rpxy-ci.that.com",
"vg1p": "rpxy..that.com",
"vg1p-internet": "rpxy-i..that.com",
"vg1np": "rpxy..that.com",
"vg1np-internet": "rpxy-i..that.com",
"vg1r7np": "rpxy.that.com",
"vg1r7np-internet": "rpxy-i.that.com",
}

fqdn_config = {
    'fqdn': 'production.pytest.that.com',
    'mode': 'http',
    'state': 'published',
    'subdomains': 'false',
    'backend': [
        'balance roundrobin',
        'option tcp-check',
        'server apilocal {} check'
    ]
}

import sys
print('usage: {} [podname ip_or_fqdn]'.format(sys.argv[0]))
if len(sys.argv) == 3:
    vpod = sys.argv[1]
    ip = sys.argv[2]
secretfile="/home/nfe/secrets/rpxy/secret.{}/admin.yml"

import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
import json
import time


headers = dict(
    Authorization='',
    accept='application/json',
    Host="api.{}".format(urls[sys.argv[1]])
)

print("header : {}".format(headers))


print("Testing : {} : https://{} ?('y' to test, ctrl+c to quit) ".format(vpod,ip))
print()

# login api
secret = yaml.load(open(secretfile.format(vpod), "r"), Loader=yaml.BaseLoader)
loginurl = "https://{}/login/name=admin/password={}".format(ip,secret['adminpassword'])
print("loginurl: {}".format(loginurl))
response = requests.get(loginurl, headers=headers, verify=False)
if response.status_code == 200:
    print("Login: success")
    token = response.json()['access_token']
else:
    print("Login: failed")
    print(response.content)
    exit(1)

# publish fqdn
fqdn = fqdn_config.copy()
fqdn['backend'][2] = fqdn_config['backend'][2].format("localhost:5080")
headers.update({"Authorization": token})
response = requests.post("https://{}/fqdn".format(ip), headers=headers, json=fqdn, verify=False)
if response.status_code != 201:
    print("Post create {} : failed".format(fqdn['fqdn']))
    print(json.dumps(response.json(), indent=2))
    input('OK to deletee entry ? or ctl-c')
    response = requests.delete("https://{}/fqdn/{}".format(ip, fqdn['fqdn']), headers=headers, json=fqdn, verify=False)
    if response.status_code != 200:
        print("Post delete {} : failed".format(fqdn['fqdn']))
        print(response.content)
        exit(1)
    else:
        print("Post delete {} : success".format(fqdn['fqdn']))
    exit(1)
else:
    print("Post create {} : success".format(fqdn['fqdn']))
    if verbose:
        print(json.dumps(response.json(), indent=2))
    print("Waiting 10 s...")
    time.sleep(10)

    # get status
    response = requests.get("https://{}/fqdn/{}/status".format(ip,fqdn['fqdn']), headers=headers, json=fqdn, verify=False)
    if response.status_code != 200:
        print("Get status {} : failed".format(fqdn['fqdn']))
        print(response.content)
    else:
        print("Get status {} : success".format(fqdn['fqdn']))
        mainkey = list(response.json().keys())[0]
        for i in response.json()[mainkey]:
            print(" on node {} : {} {}".format(i['node'],
                                               i['data'][0]['svname'],
                                               i['data'][0]['stats']['status']))
            print(" on node {} : {} {}".format(i['node'],
                                               i['data'][1]['svname'],
                                               i['data'][1]['stats']['status']))

    # test fqdn
    print("Functional test begins")
    test_headers = dict(
        Host=fqdn['fqdn'],
        accept='application/json'
    )
    response = requests.get("https://{}/swagger.json".format(ip), headers=test_headers, verify=False)
    if response.status_code != 200:
        print("Functional test {} : failed".format(fqdn['fqdn']))
        print(response.content)
    else:
        print("Functional test {} : success".format(fqdn['fqdn']))
        print(json.dumps(response.json()['info']['version'], indent=2))

    # delete fqdn
    response = input("Ok to delete {} ?(y ok)")
    if response == "y":
        response = requests.delete("https://{}/fqdn/{}".format(ip,fqdn['fqdn']), headers=headers, json=fqdn, verify=False)
        if response.status_code != 200:
            print("Post delete {} : failed".format(fqdn['fqdn']))
            print(response.content)
            exit(1)
        else:
            print("Post delete {} : success".format(fqdn['fqdn']))

