#!/usr/bin/env python3

######
# consts vars

# time to wait for backends to mount
sleeptime = 5

urls = {
    "vg1r7np-ci": "rpxy-ci.that.com",
    "vg1p": "rpxy..that.com",
    "vg1p-internet": "rpxy-i..that.com",
    "vg1np": "rpxy..that.com",
    "vg1np-internet": "rpxy-i..that.com",
    "vg1r7np": "rpxy.that.com",
    "vg1r7np-internet": "rpxy-i.that.com",
}

fqdn_config = {
    'fqdn': '{}.pytest.that.com',
    'mode': 'http',
    'state': 'published',
    'subdomains': 'false',
    'backend': [
        'balance roundrobin',
        'option tcp-check',
        'server apilocal {} check'
    ]
}

apiheader = dict(
    Authorization='',
    accept='application/json'
)


#####
# functions

def output(key=None, value=None, pre=None, post=None):
    if jsonformat:
        if pre:
            print(pre, end="")
        if key:
            print('"{}": "{}"'.format(key, value), end="")
        if post:
            print(post, end="")
    else:
        if key:
            print("{}: {}".format(key, value))


def isIp(text):
    try:
        isip = ipaddress.ip_address(text)
        return True
    except:
        return False


######
# argparsing
import argparse
import ipaddress
import dns.resolver
import hashlib
import platform

parser = argparse.ArgumentParser(description="Functional testing reverse proxy service")
parser.add_argument("target", type=str,
                    help="target in [ALL,{}]".format(",".join(urls.keys())))
parser.add_argument("--secretsdir", "-s", required=True,
                    help="dir where secret.vpodname/admin.yml are")
parser.add_argument("--ips", action="store",
                    help="a comma list of target ip address instead of stored fqdn")
parser.add_argument("--json", "-j", action="store_true",
                    help="for json output format")
parser.add_argument("--fqdncheck", "-f", action="store_true",
                    help="check all defined fqdn")
parser.add_argument("--fqdncheckfrom", "-o", action="store",
                    help="use this ip to check fqdn from")
parser.add_argument("--fqdncheckmaxerror", "-m", action="store",
                    help="exit with error 1 if fqdn check error rate > m")
parser.add_argument("--apitest", "-t", action="store",
                    help="apicheck with this fqdn")
parser.add_argument("--aliasips", "-a", action="store",
                    help="a fqdn that gives ips to nodes (api.rpxy.sss.xpod.that.com)")
parser.add_argument("--interactive", "-i", action="store_true",
                    help="for interactive behavior")
parser.add_argument("--cleanup", "-c", action="store_true",
                    help="cleanup eventualy previous testing")
parser.add_argument("--verbose", "-v", action="store_true",
                    help="for verbose output")
args = parser.parse_args()

urllist = []
interactive = args.interactive
verbose = args.verbose
target = args.target
jsonformat = args.json
fqdncheck = args.fqdncheck
fqdncheckfrom = args.fqdncheckfrom
apitest = args.apitest

if args.fqdncheckmaxerror:
    fqdncheckmaxerror = float(args.fqdncheckmaxerror)
else:
    fqdncheckmaxerror = 100

if target == "ALL":
    urllist = urls.keys()
else:
    if target in urls.keys():
        urllist = [args.target]
    else:
        print("Wrong target")
        print("Aborting.")
        exit(1)

if args.ips:
    iplist = args.ips.split(',')
    isipcheck = True
    for ip in iplist:
        if not isIp(ip):
            isipcheck = False
            break
    if not isipcheck:
        print("Error, bad ip address list".format(target, ",".join(urls.keys())))
        print("Aborting.")
        exit(1)
    urllist = iplist.copy()
else:
    iplist = None

if args.aliasips:
    try:
        ips = dns.resolver.query(args.aliasips, 'A')
    except dns.resolver.NoAnswer:
        print(" Unknown domain {}".format(args.aliasips))
        exit(1)
    for ip in ips:
        urllist.append(ip.address)
    iplist = urllist.copy()

# if fqdncheck : also include target for differential status
if fqdncheck:
    urllist.append(target)

#
if not apitest:
    apitest = hashlib.md5(platform.node().encode('utf-8')).hexdigest()

######
# summary
if fqdncheck:
    output("test", "fqdncheck", pre="{\n")
else:
    output("test", "apicheck", pre="{\n")
output("target", args.target, pre=",\n")
output("secretsdir", args.secretsdir, pre=",\n")
if args.interactive:
    output("Mode", "interactive", pre=",\n")
else:
    output("Mode", "batch", pre=",\n")
output(post=",\n[\n")

######
# vars
secretfile = "{}/secret.{{}}/admin.yml".format(args.secretsdir)
fqdnchecks = dict()
fqdncheckmaxerrortrigger = False


import yaml
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
import json
import time
import sys

######
# working loop
for u in urllist:
    ####
    # tests settings
    apiheader.update({"Host": "api.{}".format(urls[target])})
    if u in urls:
        apiurl = "https://api.{}".format(urls[u])
        if fqdncheckfrom:
            rpipurl = "https://{}".format(fqdncheckfrom)
        else:
            try:
                rpipurl = "https://{}".format(dns.resolver.query(urls[u], 'A')[0].address)
            except dns.resolver.NoAnswer:
                print(" Unknown domain {}".format(urls[u]))
                exit(1)
        vpodname = u
    else:
        apiurl = "https://{}".format(u)
        rpipurl = "https://{}".format(u)
        vpodname = target

    fqdn = fqdn_config.copy()
    fqdn['backend'][2] = fqdn_config['backend'][2].format("localhost:5080")
    fqdn['fqdn'] = fqdn_config['fqdn'].format(apitest)
    test_headers = dict(
        Host=fqdn['fqdn'],
        Accept='application/json'
    )

    # summary
    if urllist.index(u) != 0:
        output(pre=",\n")
    output("vpod", vpodname, pre="{\n", post=",\n")
    output("apiurl", apiurl, post=",\n")
    output("rpipurl", rpipurl, post=",\n")
    output("apihost", apiheader["Host"], post=",\n")
    if fqdncheck:
        output("fqdn", fqdn['fqdn'], post=",\n")
    if interactive:
        inputok = input(" ? ('y' to test, <enter> to skip, ctrl+c to quit)")
        if inputok != "y":
            print("skipped.", file=sys.stderr)
            continue

    # login api
    try:
        secret = yaml.load(open(secretfile.format(vpodname), "r"), Loader=yaml.BaseLoader)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        print("Please provide a folder where secret.vpodname/admin.yml is", file=sys.stderr)
        exit(1)
    try:
        response = requests.get("{}/login/name=admin/password={}".format(apiurl,
                                                                               secret['adminpassword']), verify=False,
                                headers=apiheader)
    except requests.exceptions.ConnectionError:
        output("api_login".format(apiurl), "failed", post="\n}")
        if verbose:
            print("Can't connect to {}".format(apiurl), file=sys.stderr)
        if target == "ALL":
            output(post=",\n")
            continue
        else:
            output(post="\n]\n}")
            exit(1)
    if response.status_code == 200:
        output("api_login".format(apiurl), "success", post=",\n")
        token = response.json()['access_token']
    else:
        output("api_login".format(apiurl), "failed", post="\n")
        if verbose:
            print(response.content, file=sys.stderr)
        if target == "ALL":
            output(post=",\n")
            continue
        else:
            output(post="\n]\n}")
            exit(1)
    apiheader.update({"Authorization": token})

    # fqdncheck
    if fqdncheck:
        response = requests.get("{}/fqdn".format(apiurl), headers=apiheader, verify=False)
        if response.status_code != 200:
            output("fqdnlist", "failed")
            if verbose:
                print(response.content, file=sys.stderr)
            if target == "ALL":
                output(post=",\n")
                continue
            else:
                output(post="\n]\n}")
                exit(1)
        output("fqdnlist", "success", post=",\n\"fqdnchecks\": {\n")
        checklist = dict()
        for f in response.json():
            test_headers.update({"Host": f["fqdn"]})
            try:
                fresp = requests.get("{}/".format(rpipurl), headers=test_headers, verify=False, timeout=5).status_code
            except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout):
                fresp = "timeout"
            except requests.exceptions.ConnectionError:
                fresp = "error"
            except requests.exceptions.TooManyRedirects:
                fresp = "redirect_error"

            if response.json().index(f) == (len(response.json()) - 1):
                output(f["fqdn"], str(fresp), post="}\n")
            else:
                output(f["fqdn"], str(fresp), post=",\n")
            checklist.update({f['fqdn']: fresp})
        fqdnchecks.update({u: checklist})
        output(post="}")
    # apicheck
    else:
        # cleanup config
        if args.cleanup:
            inputok = "y"
            if interactive:
                inputok = input("Ok to delete {} ?(y ok)".format(fqdn['fqdn']))
            if inputok == "y":
                response = requests.delete("{}/fqdn/{}".format(apiurl, fqdn['fqdn']),
                                           headers=apiheader,
                                           json=fqdn, verify=False)
                if response.status_code not in [200, 400]:
                    output("cleanup", "failed")
                    if verbose:
                        print(response.content, file=sys.stderr)
                    if target == "ALL":
                        output(post=",\n")
                        continue
                    else:
                        output(post="\n]\n}")
                        exit(1)
                else:
                    if response.status_code == 200:
                        output("cleanup", "success", post=",")
                    else:
                        output("cleanup", "nothing to cleanup here. Ok", post=",\n")

        # publish fqdn
        response = requests.post("{}/fqdn".format(apiurl),
                                 headers=apiheader, json=fqdn, verify=False)
        if response.status_code != 201:
            output("post_create", "failed")
            if verbose:
                print(json.dumps(response.json(), indent=2), file=sys.stderr)
                if target == "ALL":
                    output(post=",\n")
                    continue
                else:
                    output(post="\n]\n}")
                    exit(1)
        else:
            output("post_create", "success", post=",\n")
            if verbose:
                print(json.dumps(response.json(), indent=2), file=sys.stderr)
                print(" Waiting {} s...".format(str(sleeptime)), file=sys.stderr)
            time.sleep(sleeptime)

            # get status
            response = requests.get("{}/fqdn/{}/status".format(apiurl, fqdn['fqdn']),
                                    headers=apiheader, json=fqdn, verify=False)
            if response.status_code != 200:
                output("get_status", "failed", post=",\n")
                if verbose:
                    print(response.content, file=sys.stderr)
                if target == "ALL":
                    continue
                else:
                    exit(1)
            else:
                output("get_status", "success", post=",\n")
                if verbose:
                    mainkey = list(response.json().keys())[0]
                    for i in response.json()[mainkey]:
                        print(" on node {} : {} {}".format(i['node'],
                                                           i['data'][0]['svname'],
                                                           i['data'][0]['stats']['status']), file=sys.stderr)
                        print(" on node {} : {} {}".format(i['node'],
                                                           i['data'][1]['svname'],
                                                           i['data'][1]['stats']['status']), file=sys.stderr)

            # test fqdn
            response = requests.get("{}/swagger.json".format(apiurl),
                                    headers=test_headers, verify=False)
            if response.status_code != 200:
                output("functional_test", "failed", post=",\n")
                if verbose:
                    print(response.content, file=sys.stderr)
                if target == "ALL":
                    continue
                else:
                    exit(1)
            else:
                output("functional_test", "success", post=",\n")
                if verbose:
                    try:
                        print(json.dumps(response.json()['info']['version'], indent=2), file=sys.stderr)
                    except:
                        print(response.content, file=sys.stderr)

            # delete fqdn
            inputok = "y"
            if interactive:
                inputok = input("Ok to delete {} ?(y ok)")
            if inputok == "y":
                response = requests.delete("{}/fqdn/{}".format(apiurl, fqdn['fqdn']),
                                           headers=apiheader,
                                           json=fqdn, verify=False)
                if response.status_code != 200:
                    output("post_delete", "failed", post=",\n")
                    if verbose:
                        print(response.content, file=sys.stderr)
                    if target == "ALL":
                        continue
                    else:
                        exit(1)
                else:
                    output("post_delete", "success", post="\n}")
    if not fqdncheck:
        if verbose:
            print(" Waiting {} s ...".format(sleeptime), file=sys.stderr)
            print("------------------------------------", file=sys.stderr)
        time.sleep(sleeptime)
if fqdncheck:
    errorrate = {target: { "name": target, "len": len(fqdnchecks[target])}}
    for u in urllist:
        if u == target:
            continue
        else:
            err = []
            for f in fqdnchecks[u]:
                if f in fqdnchecks[target]:
                    if fqdnchecks[u][f] != fqdnchecks[target][f]:
                        err.append({f: "{} != {}".format(fqdnchecks[u][f], fqdnchecks[target][f])})
                else:
                    err.append({f: "absent"})
            for f in fqdnchecks[target]:
                if f not in fqdnchecks[u]:
                    err.append({f: "missing"})
            if fqdncheckmaxerror < (len(err) / len(fqdnchecks[target]))*100:
                fqdncheckmaxerrortrigger = True
            errorrate.update({u: {"error_rate": "{:.0%}".format(len(err) / len(fqdnchecks[target])),
                                  "nberr": len(err),
                                  "len": len(fqdnchecks[u]),
                                  "diff": err}})
    output(pre="],\n{\n")
    print('"FunctinalTests": {}\n}}\n}}'.format(json.dumps(errorrate, indent=2)))
else:
    output("FunctionalTests", "success", pre="],\n{\n", post="\n}\n}")
print()
if fqdncheckmaxerrortrigger:
    exit(1)
else:
    exit(0)
