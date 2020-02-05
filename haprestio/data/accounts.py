import yaml, logging, bcrypt
from .data import *


class Accounts(DataCasting, object):
    def __init__(self, admin="", password=""):
        super().__init__('acct')
        self.accounts = []
        for u in self.list():
            self.accounts.append(Account(u))
        if not self.accounts:
            logging.info("Initial configuration {} {}".format(admin, password))
            self.add(admin)
            Account(admin).change(password)

    @property
    def key(self):
        return self.cast

    @property
    def value(self):
        return self.accounts

    def __repr__(self):
        return str(self.accounts)

    def __len__(self):
        return len(self.accounts)

    def __iter__(self):
        self.iter = 0
        return self

    def __next__(self):
        if self.iter < len(self.accounts):
            self.iter = self.iter + 1
            return str(self.accounts[self.iter - 1])
        raise StopIteration()

    # noinspection PyBroadException
    def load_yaml(self, file):
        try:
            with open(file, 'r') as f:
                acct_list = yaml.load(f, Loader=yaml.SafeLoader)
                f.close()
        except Exception:
            acct_list = {}
        for acct in acct_list:
            password = acct_list[acct]
            self.add(acct)
            Account(acct).update(password)
        return self.list()

    def dict(self, **kwargs):
        result = []
        d = super().dict()
        for i in d:
            result.append({'login': i, 'password': d[i]})
        return result


class Account(DataCasting, object):
    def __init__(self, login=None):
        super().__init__('acct')
        self.login = login
        if login is not None:
            self.password = self.get()

    @property
    def key(self):
        return self.login

    @property
    def value(self):
        return self.password

    @classmethod
    def create(cls, payload):
        result = cls(payload['login'])
        result.save()
        result.change(payload['password'])
        return result

    def json(self):
        return {'login': self.login, 'password': self.password}

    def __repr__(self):
        return self.login

    def getPath(self):
        return super().getPath() + self.login

    def change(self, password):
        if not self.exists():
            return False
        self.password = self.hashpass(password)
        super().save()
        return self

    def check(self, password):
        return self.hashcheck(self.password, password)

    @staticmethod
    def hashpass(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def hashcheck(hashed, password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
