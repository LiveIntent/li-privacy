import jwt
import json
import requests

class ApiClient(object):
    def __init__(self, hostname, rsa_key, verbose):
        self.verbose = verbose
        self.rsa_key = rsa_key
        self.hostname = hostname

    def encode_jwt(self, payload):
        return jwt.encode(payload, self.rsa_key, algorithm="RS256")

    def wrap_jwt(self, jwt):
        return { "jwt": jwt }

    def send_request(self, path, body):
        url = "https://{}/{}".format(self.hostname, path)
        if(self.verbose):
            print("Curl equivalent:\n curl -X POST -H 'Content-type: application/json' -d '{data}' '{url}'".format(data=json.dumps(body), url=url))
        return requests.post(url, json=body)

    def submit(self, request):
        jwt = self.encode_jwt(request.json()) 
        body = self.wrap_jwt(jwt)
        return self.send_request(request.path, body)
