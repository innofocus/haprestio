import json, requests

from haprestio import app, Accounts, Account, Certs, Cert, Fqdns, Fqdn, Config, Endpoint

from test_base import pyt_fqdn_base, pyt_account, pyt_url, pyt_admin, pyt_endusers, pyt_headers, pyt_login, same_entry, fqdn_config, login_enduser

pyt_cert = {
    'file': 'test_cert.pem',
    'name': 'pytest',
    'type': 'application/x-x509-ca-cert'
}
pyt_fqdn_config = {
    'fqdn': 'pytest.that.com',
    'mode': 'http',
    'state': 'published',
    'subdomains': 'true',
    'backend': [
        'balance roundrobin',
        'server srv01 10.0.0.10:8080 weight 1 maxconn 100',
        'server srv02 10.0.0.11:8080 weight 1 maxconn 100'
    ],
    'message': []
}
pyt_fqdn_config_bad = {
    'fqdn': 'pytest.that.com',
    'mode': 'http',
    'state': 'published',
    'subdomains': 'true',
    'backend': [
        'buggyword roundrobin',
        'server srv01 10.0.0.10:8080 weight 1 maxconn 100',
        'server srv02 10.0.0.11:8080 weight 1 maxconn 100'
    ],
    'message': []
}

pyt_fqdn_base = 'pytest.that.com'

pyt_fqdn_config_updated = {
    'fqdn': 'pytest.that.com',
    'mode': 'http',
    'state': 'published',
    'subdomains': 'true',
    'backend': [
        'balance roundrobin',
        'option httpchk',
        'server srv01 10.0.0.10:8080 weight 1 maxconn 100 check',
        'server srv02 10.0.0.11:8080 weight 1 maxconn 100 check',
        'server srv03 10.0.0.12:8080 weight 1 maxconn 100 check'
    ],
    'message': []
}

pyt_fqdn_config_updated2 = pyt_fqdn_config_updated.copy()
pyt_fqdn_config_updated2['subdomains'] = 'false'
pyt_fqdn_config_updated3 = pyt_fqdn_config_updated.copy()
pyt_fqdn_config_updated2['subdomains'] = 'false'

## prepare config when rerun
def test_cleanup():
    print('Cleanup previous pytest run...')
    for i in pyt_endusers:
        Account(i['username']).delete()
        if Fqdn(i['username']+"-"+pyt_fqdn_base).exists():
            Fqdn(i['username']+"-"+pyt_fqdn_base).destroy()
    Cert(pyt_cert['name']).delete()
    assert True

def test_login_admin():
    url = pyt_login.format(login=pyt_admin['username'], password=pyt_admin['password'])
    token = requests.get(url).json()['access_token']
    assert token != None
    pyt_headers['Authorization'] = token
    return token


def test_create_endusers():
    test_login_admin()
    for enduser in pyt_endusers:
        response = requests.post(pyt_url + '/account', headers=pyt_headers,
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
        response = requests.get(pyt_url + '/fqdn', headers=pyt_headers).json()
        assert len(response) == num_fqdns


def test_fqdn_create_bad():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config_bad)
        response = requests.post(pyt_url + '/fqdn', headers=pyt_headers,
                                 json=config).json()
        assert response['state'] == "publish_failed"
        assert response['message'] != ""


def test_fqdn_create():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config)
        response = requests.post(pyt_url + '/fqdn', headers=pyt_headers,
                                 json=config).json()
        assert same_entry(response,config)


def test_fqdn_get():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config)
        response = requests.get(pyt_url + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()
        assert same_entry(response,config)


def test_fqdn_update_bad():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config_bad)
        response = requests.put(pyt_url + '/fqdn/' + config['fqdn'], headers=pyt_headers,
                                json=config).json()
        assert response['state'] == "publish_failed"
        assert response['message'] != ""


def test_fqdn_get_update_bad():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config_bad)
        response = requests.get(pyt_url + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()

        config['state'] = "publish_failed"
        assert same_entry(response,config)


def test_fqdn_update():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config_updated)
        response = requests.put(pyt_url + '/fqdn/' + config['fqdn'], headers=pyt_headers,
                                json=config).json()
        assert same_entry(response,config)


def test_fqdn_get_updated():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config_updated)
        response = requests.get(pyt_url + '/fqdn/' + config['fqdn'], headers=pyt_headers).json()
        assert same_entry(response,config)


def test_unpublish_fqdn():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config_updated)
        response = requests.delete(pyt_url + '/publish/' + config['fqdn'], headers=pyt_headers).json()
        assert response['state'] == "unpublish"


def test_publish_fqdn():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        config = fqdn_config(enduser, pyt_fqdn_config_updated)
        response = requests.put(pyt_url + '/publish/' + config['fqdn'], headers=pyt_headers).json()
        assert response['state'] == "published"


def test_unpublish_all():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.delete(pyt_url + '/publish', headers=pyt_headers).json()
        assert response[0]['state'] == "unpublish"


def test_publish_all():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.put(pyt_url + '/publish', headers=pyt_headers).json()
        assert response[0]['state'] == "published"


def test_cert_list():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.get(pyt_url + '/cert', headers=pyt_headers).json()
        assert len(response) == 0


def test_cert_create():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.post(pyt_url + '/cert?name=' + enduser['username'] + '-' +pyt_cert['name'],
                                 headers=pyt_headers,
                                 files={'file': (pyt_cert['file'],
                                                 open(pyt_cert['file'], 'rb'),
                                                 pyt_cert['type'])}).json()


        print(json.dumps(response, indent=2))
        assert response['state'] == "published"

def test_cert_list():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.get(pyt_url + '/cert', headers=pyt_headers).json()
        assert len(response) == 1
        assert response[0]['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response[0]['state'] == "published"


def test_cert_unpublish():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.delete(pyt_url + '/cert/' + enduser['username'] + '-' + pyt_cert['name'], headers=pyt_headers).json()
        assert response['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response['state'] == "unpublished"


def test_cert_publish():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.put(pyt_url + '/cert/' + enduser['username'] + '-' + pyt_cert['name'], headers=pyt_headers).json()
        assert response['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response['state'] == "published"


def test_cert_publish_all():
    for enduser in pyt_endusers:
        login_enduser(enduser)
        response = requests.put(pyt_url + '/cert', headers=pyt_headers).json()
        assert len(response) == 1
        assert response[0]['cert'] == enduser['username'] + '-' + pyt_cert['name']
        assert response[0]['state'] == "published"


def test_delete_enduser():
    test_login_admin()
    for enduser in pyt_endusers:
        response = requests.delete(pyt_url + '/account/' + enduser['username'], headers=pyt_headers).json()
        assert response