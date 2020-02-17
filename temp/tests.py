import requests

from haprestio import app, Accounts, Account, Certs, Cert, Fqdns, Fqdn, Config, Endpoint

pyt_user = "nico"
pyt_password = "nico"
pyt_admin = app.config['RAPIXYADMIN']
pyt_adminpass = app.config['INITPASS']
pyt_url = 'http://'+app.config['HOST']+':'+app.config['PORT']
pyt_login = "/login/name={login}/password={password}"
pyt_fqdn_url = "/fqdn"
pyt_fqdn_http = {'fqdn': 'pytest.that.com', 'mode': 'http', 'state': 'publish',
             'backend': ['balance roundrobin', 'server srv01 10.0.0.10:443 weight 1 maxconn 100']}
pyt_fqdn_tcp = {'fqdn': 'pytest-tcp.that.com', 'mode': 'tcp', 'state': 'publish',
             'backend': ['balance roundrobin', 'server srv01 10.0.0.10:443 weight 1 maxconn 100']}

pyt_headers = dict(
    Authorization='',
    accept='application/json'
)
pyt_publish_url = '/publish'
pyt_cert_url = '/cert'


def test_ops_load_users():
    test_login_admin()
    response = requests.get(pyt_url + '/ops/load_users', headers=pyt_headers).json()
    assert len(response) == 3

def test_ops_load_fqdns():
    test_login_admin()
    response = requests.get(pyt_url + '/ops/load_fqdns', headers=pyt_headers).json()
    assert len(response) == 6

def test_ops_load_certs():
    test_login_admin()
    response = requests.get(pyt_url + '/ops/load_certs', headers=pyt_headers).json()
    assert len(response) == 5

def test_ops_load_localpipe():
    test_login_admin()
    response = requests.get(pyt_url + '/ops/load_localpipe', headers=pyt_headers).json()
    assert response['option'] == 'localpipe'


def test_Accounts():
    assert len(Accounts()) == 3
    if 'user' in Accounts():
        assert Accounts().delete('user') == True
    assert Accounts().add('user') == True
    Account('user').change('password')
    assert Account('user').password == 'PASSWORD'
    Account('user').change('sdfsdfsdjio')
    assert Account('user').password != 'PASSWORD'
    Accounts().delete('user')
    assert Accounts().delete('user') == False
    assert Account('user').change('password') == False


def test_Fqdns():
    x = list(Fqdns())[0]
    x_v = Fqdn(x).dict()
    assert Fqdns().delete(x) == True
    assert Fqdns().delete(x) == False
    assert str(Fqdns().add(x)) == x
    assert Fqdn(x).dict() != x_v
    Fqdn(x).update(x_v)
    assert Fqdn(x).dict() == x_v


def test_Certs():
    x = list(Certs())[0]
    x_v = Cert(x).dict()
    assert Certs().delete(x) == True
    assert Certs().delete(x) == False
    assert Certs().add(x) == True
    assert Cert(x).dict() != x_v
    Cert(x).update(x_v)
    assert Cert(x).dict() == x_v


def test_login_admin():
    url = "{0}{1}".format(pyt_url, pyt_login.format(login=pyt_admin, password=pyt_adminpass))
    admintoken = requests.get(url).json()['access_token']
    assert admintoken != None
    pyt_headers['Authorization'] = admintoken
    return admintoken

def test_add_user():
    Account(pyt_user).change(pyt_password)
    users = requests.get(pyt_url + '/account', headers=pyt_headers).json()
    checkpass = ""
    for i in users:
        if i['login'] == pyt_user:
            checkpass = i['password']
    assert Account(pyt_user).hashpass(pyt_password) == checkpass
    newuser = requests.post(pyt_url + '/account', headers=pyt_headers,
                            json={"login": "loginuser", "password": "loginuser"}).json()
    assert newuser == {"login": "loginuser", "password": "LOGINUSER"}



def test_login_user():
    token = requests.get(pyt_url + pyt_login.format(login=pyt_user, password=pyt_password)).json()['access_token']
    assert token != None
    pyt_headers['Authorization'] = token
    return token


def test_api_fqdn_add_http():
    Fqdns().delete(pyt_fqdn_http['fqdn'], recurse=True)
    response = requests.post(pyt_url + pyt_fqdn_url, json=pyt_fqdn_http, headers=pyt_headers).json()
    assert response == pyt_fqdn_http

def test_api_fqdn_add_tcp():
    Fqdns().delete(pyt_fqdn_tcp['fqdn'], recurse=True)
    response = requests.post(pyt_url + pyt_fqdn_url, json=pyt_fqdn_tcp, headers=pyt_headers).json()
    assert response == pyt_fqdn_tcp

def test_api_fqdn_list():
    response = requests.get(pyt_url + pyt_fqdn_url, json=pyt_fqdn_http, headers=pyt_headers).json()
    x = Fqdns().json(pyt_user)
    for i in x:
        i.pop('owner')
    assert x == response
    assert pyt_fqdn_http in response


def test_api_fqdn_get():
    response = requests.get(pyt_url + pyt_fqdn_url + '/' + pyt_fqdn_http['fqdn'], json=pyt_fqdn_http, headers=pyt_headers).json()
    assert pyt_fqdn_http == response


def test_api_fqdn_delete():
    response = requests.get(pyt_url + pyt_fqdn_url + '/' + pyt_fqdn_http['fqdn'], json=pyt_fqdn_http, headers=pyt_headers).json()
    assert 'publish' in response['state']
    response = requests.delete(pyt_url + pyt_fqdn_url + '/' + pyt_fqdn_http['fqdn'], headers=pyt_headers).json()
    assert 'remove' in response['state']


def test_api_fqdn_update():
    pyt_fqdn_http['backend'][1] = 'server srv01 10.0.0.20'
    response = requests.put(pyt_url + pyt_fqdn_url + '/' + pyt_fqdn_http['fqdn'], json=pyt_fqdn_http, headers=pyt_headers).json()
    assert pyt_fqdn_http == response


def test_api_fqdn_pub():
    response = requests.put(pyt_url + pyt_publish_url + '/' + pyt_fqdn_http['fqdn'], headers=pyt_headers).json()
    assert response['state'] == 'published'
    assert response['fqdn'] == pyt_fqdn_http['fqdn']

    response = requests.put(pyt_url + pyt_publish_url + "/rpxy.that.com", headers=pyt_headers).json()
    assert response['state'] == 'published'
    assert response['fqdn'] == "rpxy.that.com"


def test_api_fqdn_pub():
    response = requests.delete(pyt_url + pyt_publish_url + '/' + pyt_fqdn_http['fqdn'], headers=pyt_headers).json()
    assert response['state'] == 'removed'
    assert response['fqdn'] == pyt_fqdn_http['fqdn']


def test_api_fqdn_pub_all():
    response = requests.put(pyt_url + pyt_publish_url, headers=pyt_headers).json()
    return response


def test_api_cert_list():
    x = Certs().json(pyt_user)
    for i in x:
        i.pop('content')
        i.pop('owner')
    response = requests.get(pyt_url + pyt_cert_url, headers=pyt_headers).json()
    assert x == response


def test_api_cert_pub_unauthorized():
    cert = list(Certs())[0]
    response = requests.put(pyt_url + pyt_cert_url + '/' + cert, headers=pyt_headers).json()
    assert response['message'] == "you don't own this certificate"

def test_api_cert_pub():
    cert = 'certif'
    response = requests.put(pyt_url + pyt_cert_url + '/' + cert, headers=pyt_headers).json()
    assert 'publish' in response['state']

def test_api_cert_unpub():
    cert = 'certif'
    response = requests.delete(pyt_url + pyt_cert_url + '/' + cert, headers=pyt_headers).json()
    assert 'remove' in response['state']

