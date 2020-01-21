from __future__ import print_function
import json
import jwt
import time
import requests
import li_privacy.hash_utility as hash_utility

class DSR(object):
    def __init__(self, operation, domain_name, scope, callback_url, key_id, rsa_key, endpoint, verbose=False):
        self.verbose = verbose
        self.operation = operation
        self.domain_name = domain_name
        self.scope = scope
        self.key_id = key_id
        self.rsa_key = rsa_key
        self.callback_url = callback_url
        self.endpoint = endpoint

    def constructPayload(self, user, request_id=None):
        hashes = hash_utility.hash_utility().getHashes(user)
        request_id = request_id or hashes[0]
        now = int(time.time())
        payload = { 
            "iss": "CN=" + self.domain_name,
            "aud": self.endpoint,
            "cnf": {
                "kid": self.key_id
            },
            "jti": request_id,
            "iat": now,
            "exp": now + 3600,
            "dsr": {
                "type": self.operation,
                "scope": self.scope,
                "identifiers": [
                    {
                        "type": "EMAIL_HASH",
                        "values": hashes
                    }
                ]
            }
        }
        # Set the optional callback_url if specified
        callback_url = self.callback_url
        if(callback_url is not None):
            payload['dsr']['target'] = callback_url

        if(self.verbose):
            print("JSON payload to encode " + json.dumps(payload, indent=2))
        return payload

    def encodeJWT(self, payload):
        result = jwt.encode(payload, self.rsa_key, algorithm="RS256").decode('utf-8')
        if(self.verbose):
            print()
            print("Encoded JWT " + json.dumps(result, indent=2))
        return result

    def wrapJWT(self, jwt):
        return { "jwt": jwt }

    def sendRequest(self, body):
        return requests.post("https://{}/dsr".format(self.endpoint), json=body)

    def submit(self, entry, request_id):
        payload = self.constructPayload(entry, request_id)
        jwt = self.encodeJWT(payload) 
        body = self.wrapJWT(jwt)
        response = self.sendRequest(body)
        return (payload, response)
