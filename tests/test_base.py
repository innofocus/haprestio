import requests, json
from haprestio import app

pyt_combinatory = {
    "modes": ['tcp','http'],
    "subdomains": ['true','false'],
    "buggyclient": ['true','false']
}

pyt_admin = {
    'username': 'admin',
    'password': 'admin'
}
pyt_account = {
    'username': 'netcraftmen',
    'password': 'netcraftmen'
}
pyt_endusers = [
    {
        'username': 'user1',
        'password': 'pass1'
    },
    {
        'username': 'user2',
        'password': 'pass2'
    }
]

pyt_url = 'http://{}:{}'.format('haprestio', app.config['PORT'])
pyt_apiloc = app.config['DEFAULT_LOCATION']
pyt_login = pyt_url + "/adm/login/name={login}/password={password}"

pyt_headers = dict(
    Authorization='',
    accept='application/json'
)

pyt_fqdn_base = 'pytest.that.com'


def same_entry(response, model):
    spiid = response['spiid']
    message = response['message']
    response.pop('spiid')
    response['message'] = []
    if response != model:
        print('response:\n')
        print('spiid: {}'.format(spiid))
        print('message: {}'.format(message))
        print(json.dumps(response,indent=2))
        print('model:\n')
        print(json.dumps(model,indent=2))
    return response == model

def fqdn_config(enduser, mode, subdom, config):
    ret = config
    ret['fqdn'] = '{}-{}-{}-{}'.format(enduser['username'], mode, "subdom"+subdom, pyt_fqdn_base)
    return ret

def login_enduser(enduser):
    response = requests.get(pyt_login.format(login=enduser['username'], password=enduser['password'])).json()
    pyt_headers['Authorization'] = response['access_token']
    return response

