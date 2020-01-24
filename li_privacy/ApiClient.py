import jwt
import json
import requests

class ApiClient(object):
    def __init__(self, endpoint, rsa_key, verbose):
        self.verbose = verbose
        self.rsa_key = rsa_key
        self.endpoint = endpoint

    def encode_jwt(self, payload):
        return jwt.encode(payload, self.rsa_key, algorithm="RS256").decode('utf-8')

    def wrap_jwt(self, jwt):
        return { "jwt": jwt }

    def send_request(self, path, body):
        return requests.post("https://{}/{}".format(self.endpoint, path), json=body)

    def submit(self, request):
        jwt = self.encode_jwt(request.json()) 
        body = self.wrap_jwt(jwt)
        if(self.verbose):
            print()
            print("Request body: " + json.dumps(body))
        return self.send_request(request.path, body)
