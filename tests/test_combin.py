import json, requests, pytest
import subprocess, os

#from haprestio import app
from haprestio.data.endpoints import Endpoint
from haprestio.data.accounts import Accounts, Account
from haprestio.data.fqdns import Fqdns, Fqdn
from haprestio.data.certs import Certs, Cert
from haprestio.helpers.helpers import Config

from test_base import pyt_combinatory, pyt_fqdn_base, pyt_account, pyt_url, pyt_apiloc, pyt_admin, pyt_endusers, pyt_headers, pyt_login, same_entry, fqdn_config, login_enduser

pyt_fqdn_base = 'pytest.that.com'

pyt_cert = {
    'file': 'pytest.pem',
    'name': 'pytest',
    'fqdn': pyt_fqdn_base,
    'type': 'application/x-x509-ca-cert'
}
pyt_fqdn_config = {
    'fqdn': pyt_fqdn_base,
    'mode': 'http',
    'state': 'published',
    'subdomains': 'false',
    'buggyclient': 'false',
    'backend': [
        'balance roundrobin',
        'server srv01 10.0.0.10:8080 weight 1 maxconn 100',
        'server srv02 10.0.0.11:8080 weight 1 maxconn 100'
    ],
    'message': []
}
pyt_fqdn_config_bad = {
    'fqdn': pyt_fqdn_base,
    'mode': 'http',
    'state': 'published',
    'subdomains': 'false',
    'buggyclient': 'false',
    'backend': [
        'buggyword roundrobin',
        'server srv01 10.0.0.10:8080 weight 1 maxconn 100',
        'server srv02 10.0.0.11:8080 weight 1 maxconn 100'
    ],
    'message': []
}


pyt_fqdn_config_updated = {
    'fqdn': pyt_fqdn_base,
    'mode': 'http',
    'state': 'published',
    'subdomains': 'false',
    'buggyclient': 'false',
    'backend': [
        'balance roundrobin',
        'option httpchk',
        'server srv01 10.0.0.10:8080 weight 1 maxconn 100 check',
        'server srv02 10.0.0.11:8080 weight 1 maxconn 100 check',
        'server srv03 10.0.0.12:8080 weight 1 maxconn 100 check'
    ],
    'message': []
}

@pytest.fixture
def main():
    from . import api_v1
    api_v1.init()

    from . import adm_v1
    adm_v1.init()


## prepare config when rerun
def test_cleanup():
    print('Cleanup previous pytest run...')
    for i in pyt_endusers:
        Account(i['username']).delete()
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                fqdn = fqdn_config(i, mode, subdom, pyt_fqdn_config)["fqdn"]
                if Fqdn(fqdn).exists():
                    Fqdn(fqdn).destroy()
    Cert(pyt_cert['name']).delete()
    assert True

def test_generate_cert():
    if os.path.exists('./{}'.format(pyt_cert['file'])):
        print("{} already present".format(pyt_cert['file']))
        assert True
        return True

    from OpenSSL import crypto, SSL
    from socket import gethostname
    from pprint import pprint
    from time import gmtime, mktime
    from os.path import exists, join

    def create_self_signed_cert(cert_dir, pemfile, fqdn):
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "FR"
        cert.get_subject().ST = "France"
        cert.get_subject().L = "here"
        cert.get_subject().O = "that"
        cert.get_subject().OU = "vpod"
        cert.get_subject().CN = fqdn
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        open(join(cert_dir, pemfile), "w").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        open(join(cert_dir, pemfile), "a").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    create_self_signed_cert(".",pyt_cert['file'], pyt_fqdn_base)
    print("{} generated".format(pyt_cert['file']))
    assert True
    return True

def test_login_admin():
    url = pyt_login.format(login=pyt_admin['username'], password=pyt_admin['password'])
    token = requests.get(url).json()['access_token']
    assert token != None
    pyt_headers['Authorization'] = token
    return token


def test_create_endusers():
    test_login_admin()
    for enduser in pyt_endusers:
        response = requests.post(pyt_url + '/adm/account', headers=pyt_headers,
                                 json={"login": enduser['username'], "password": enduser['password']}).json()
        assert response['login'] == enduser['username']

def test_login_endusers():
    for enduser in pyt_endusers:
        response = login_enduser(enduser)
        assert not response == "{'message': 'Bad credentials'}"


def test_fqdn_list():
    for enduser in pyt_endusers:
        num_fqdns = 0
        for i in Fqdns().list():
            if Fqdn(i).owner == enduser['username']:
                num_fqdns += 1
        login_enduser(enduser)
        response = requests.get(pyt_url + pyt_apiloc + '/fqdn', headers=pyt_headers).json()
        assert len(response) == num_fqdns


def test_fqdn_create_bad():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_bad)
                response = requests.post(pyt_url + pyt_apiloc + '/fqdn', headers=pyt_headers,
                                         json=config).json()
                assert response['state'] == "publish_failed"
                assert response['message'] != ""


def test_fqdn_create():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config)
                response = requests.post(pyt_url + pyt_apiloc + '/fqdn', headers=pyt_headers,
                                         json=config).json()
                assert same_entry(response,config)


def test_fqdn_get():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config)
                response = requests.get(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()
                assert same_entry(response,config)


def test_fqdn_update_bad():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_bad)
                response = requests.put(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers,
                                        json=config).json()
                assert response['state'] == "publish_failed"
                assert response['message'] != ""


def test_fqdn_get_update_bad():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_bad)
                response = requests.get(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()

                config['state'] = "publish_failed"
                assert same_entry(response,config)


def test_fqdn_update():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                response = requests.put(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers,
                                        json=config).json()
                assert same_entry(response,config)


def test_fqdn_get_updated():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                response = requests.get(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()
                assert same_entry(response,config)

def test_fqdn_change_mode():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                mode_i = pyt_combinatory['modes'].index(mode)
                config['mode'] = pyt_combinatory['modes'][(mode_i+1)%2]
                response = requests.put(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers,
                                        json=config).json()
                assert same_entry(response,config)


def test_fqdn_get_changed_mode():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                mode_i = pyt_combinatory['modes'].index(mode)
                config['mode'] = pyt_combinatory['modes'][(mode_i+1)%2]
                response = requests.get(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()
                assert same_entry(response,config)

def test_fqdn_change_subdom():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                subdom_i = pyt_combinatory['subdomains'].index(subdom)
                config['subdomains'] = pyt_combinatory['subdomains'][(subdom_i+1)%2]
                response = requests.put(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers,
                                        json=config).json()
                assert same_entry(response,config)


def test_fqdn_get_changed_subdom():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                subdom_i = pyt_combinatory['subdomains'].index(subdom)
                config['subdomains'] = pyt_combinatory['subdomains'][(subdom_i + 1) % 2]
                response = requests.get(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()
                assert same_entry(response,config)

def test_fqdn_change_buggyclient():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['buggyclient']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                subdom_i = pyt_combinatory['buggyclient'].index(subdom)
                config['buggyclient'] = pyt_combinatory['buggyclient'][(subdom_i+1)%2]
                response = requests.put(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers,
                                        json=config).json()
                assert same_entry(response,config)


def test_fqdn_get_changed_buggyclient():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['buggyclient']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                subdom_i = pyt_combinatory['buggyclient'].index(subdom)
                config['buggyclient'] = pyt_combinatory['buggyclient'][(subdom_i + 1) % 2]
                response = requests.get(pyt_url + pyt_apiloc + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()
                assert same_entry(response,config)


def test_unpublish_fqdn():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                response = requests.delete(pyt_url + pyt_apiloc + '/publish/fqdn/' + config['fqdn'], headers=pyt_headers).json()
                assert response['state'] == "unpublish"


def test_publish_fqdn():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        for mode in pyt_combinatory['modes']:
            for subdom in pyt_combinatory['subdomains']:
                config = fqdn_config(enduser, mode, subdom, pyt_fqdn_config_updated)
                response = requests.put(pyt_url + pyt_apiloc + '/publish/fqdn/' + config['fqdn'], headers=pyt_headers).json()
                assert response['state'] == "published"


def test_unpublish_all():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.delete(pyt_url + pyt_apiloc + '/publish/fqdn', headers=pyt_headers).json()
        assert response[0]['state'] == "unpublish"


def test_publish_all():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.put(pyt_url + pyt_apiloc + '/publish/fqdn', headers=pyt_headers).json()
        assert response[0]['state'] == "published"


def test_cert_list():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.get(pyt_url + pyt_apiloc + '/cert', headers=pyt_headers).json()
        assert len(response) == 0


def test_cert_create():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.post(pyt_url + pyt_apiloc + '/cert?name=' + enduser['username'] + '-' +pyt_cert['name'],
                                 headers=pyt_headers,
                                 files={'file': (pyt_cert['file'],
                                                 open(pyt_cert['file'], 'rb'),
                                                 pyt_cert['type'])}).json()


        print(json.dumps(response, indent=2))
        assert response['state'] == "published"

def test_cert_list():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.get(pyt_url + pyt_apiloc + '/cert', headers=pyt_headers).json()
        assert len(response) == 1
        assert response[0]['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response[0]['state'] == "published"


def test_cert_unpublish():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.delete(pyt_url + pyt_apiloc + '/publish/cert/' + enduser['username'] + '-' + pyt_cert['name'], headers=pyt_headers).json()
        assert response['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response['state'] == "unpublished"


def test_cert_publish():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.put(pyt_url + pyt_apiloc + '/publish/cert/' + enduser['username'] + '-' + pyt_cert['name'], headers=pyt_headers).json()
        assert response['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response['state'] == "published"


def test_cert_publish_all():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.put(pyt_url + pyt_apiloc + '/publish/cert', headers=pyt_headers).json()
        assert len(response) == 1
        assert response[0]['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response[0]['state'] == "published"


def test_delete_enduser():
    test_login_admin()
    for enduser in pyt_endusers:
        response = requests.delete(pyt_url + '/adm/account/' + enduser['username'], headers=pyt_headers).json()
        assert response