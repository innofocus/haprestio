from .data import *


class Endpoints(DataEndpoints, object):
    def __init__(self, stage, bonnet, mode=None):
        super().__init__(stage, bonnet, mode)

    def __repr__(self):
        return self.stage.__repr__() + '/' + self.endpoint


class Endpoint(DataEndpoints, object):
    """ stage in pending, testing, ...
    bonnet in frontends, backends, certs
    mode in tcp, http or None
    endp in key name"""

    def __init__(self, stage, bonnet, mode, endp, spiid=None):
        super().__init__(stage, bonnet, mode, spiid)
        self.endp = endp
        self.content = self.get(endp)

    @property
    def key(self):
        return self.key

    @property
    def value(self):
        return self.content

    @classmethod
    def create(cls, stage, bonnet, mode, endp, content):
        result = cls(stage, bonnet, mode, endp)
        result.update(content)
        return result

    def __repr__(self):
        return self.stage.__repr__() + '/' + self.endpoint + '/' + self.endp

    def getPath(self):
        return super().getPath() + self.endp
