import jwt
import json
import datetime
import hashlib
import requests

def sanitizeEmail(email_address):
    return email_address.encode('utf-8').strip().lower()

def getHashes(email_address):
    return [
        hashlib.md5(email_address).hexdigest(),
        hashlib.sha1(email_address).hexdigest(),
        hashlib.sha256(email_address).hexdigest()
    ]

def constructPayload(args, config, operation):
    hashes = getHashes(sanitizeEmail(args.email_address))

    # Construct the request payload
    now = datetime.datetime.now()
    payload = { 
        "iss": "CN=" + config['domain_name'],
        "aud": config['endpoint'],
        "cnf": {
            "kid": config["key_id"]
        },
        "jti": hashes[0],
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        "dsr": {
            "type": operation,
            "scope": args.scope,
            "identifiers": [
                {
                    "type": "EMAIL_HASH",
                    "values": hashes
                }
            ]
        }
    }
    # Set the optional callback_url if specified
    callback_url = args.callback_url or config.get('callback_url')
    if(callback_url is not None):
        payload['dsr']['target'] = callback_url

    return payload

def encodeJWT(payload, config):
    with open(config["signing_key"]) as key_file:
        rsa_key = key_file.read()
    return jwt.encode(payload, rsa_key, algorithm="RS256").decode('utf-8')

def submitRequest(to_send, args, config):
    url = config["endpoint"] + "/dsr"
    return requests.post(url, json=to_send)

def printHeaders(response):
    print("HTTP/1.1 " + str(response.status_code) + " " + response.reason)
    for key,value in response.headers.items():
        print(key + ": " + value)
    print()

class dsr(object):
    def __init__(self, operation):
        self.operation = operation
    def exec(self, args):
        # Read the config file
        if args.verbose:
            print("Loading configuration from %s" % args.config)
        with open(args.config) as config_json:
            config = json.load(config_json)
        if args.verbose:
            print("Loaded configuration %s" % json.dumps(config, indent=2))
        
        if args.staging:
            config['endpoint'] = "https://gdpr-test.cph.liveintent.com"
        else:
            config['endpoint'] = "https://privacy.liadm.com"
        if args.verbose:
            print("Staging=%s, Set API endpoint to %s" % (args.staging, config['endpoint']))

        payload = constructPayload(args, config, self.operation)
        if(args.verbose):
            print("JSON payload to encode " + json.dumps(payload, indent=2))

        jwt = encodeJWT(payload, config) 
        to_send = { "jwt": jwt }
        if(args.verbose):
            print()
            print("Encoded JWT to send" + json.dumps(to_send, indent=2))

        response = submitRequest(to_send, args, config)
        if(not response.ok):
            print("ERROR: API call returned an error.")
            print()
            printHeaders(response)
        else:
            if(args.verbose):
                print("Response received")
                print()
                printHeaders(response)
        print(response.text)
