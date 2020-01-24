from __future__ import print_function
import json
import time

class Request(object):
    """Represents a request payload to the li-privacy API"""

    def __init__(self, operation, path, domain_name, key_id, callback_url, scope=None, identifiers=None, request_id=None, iat=int(time.time()), expires_in=None):
        self.operation = operation
        self.path = path
        self.domain_name = domain_name
        self.key_id = key_id
        self.callback_url = callback_url
        self.scope = scope
        self.identifiers = identifiers
        self.request_id = request_id or str(iat)
        self.iat = iat

        self.expires_in = expires_in or 3600 # 1 Hour

    def json(self):
        payload = { 
            "iss": "CN={}".format(self.domain_name),
            "aud": "privacy-api.liveintent.com",
            "cnf": {
                "kid": self.key_id
            },
            "jti": self.request_id,
            "iat": self.iat,
            "exp": self.iat + self.expires_in,
            "dsr": {
                "type": self.operation
            }
        }
        # Optional fields
        if self.scope is not None:
            payload['dsr']['scope'] = self.scope
        if self.identifiers is not None:
            payload['dsr']['identifiers'] = self.identifiers.json()
        if self.callback_url is not None:
            payload['dsr']['target'] = self.callback_url
        return payload

    def __repr__(self):
        return json.dumps(self.json())
