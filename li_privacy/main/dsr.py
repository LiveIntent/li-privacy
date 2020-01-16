import jwt
import json
import datetime
import hashlib
import requests

class DSR(object):
    def __init__(self, parser, operation):
        self.operation = operation

        # Setup parser arguments
        parser.add_argument("--config", type=str, default="config.json", \
                help="path to configuration file (Defaults to config.json)")
        parser.add_argument("--scope", type=str, \
                choices=["US_PRIVACY","EU_PRIVACY"], \
                help="jurisdiction under which the the request is submitted. (Defaults to US_PRIVACY)")
        parser.add_argument("--callback_url", type=str, \
                help="callback url to be invoked.")
        parser.add_argument("--verbose", "-v", action="store_true", \
                help="enable verbose output")
        parser.add_argument("--staging", action="store_true", \
                help="send to staging environment instead of production.")
        parser.add_argument("--request_id", \
                help="Request ID to be submitted for tracking")
        parser.add_argument("email_address", type=str, \
                help="the email address (or @filename of emails) to process")
        parser.set_defaults(func=self.exec)

        # Setup properties
        self.callback_url = None
        self.request_id = None
        self.verbose = False
        self.staging = False
        self.scope = None
        self.domain_name = None
        self.signing_key = None
        self.endpoint = None
        self.key_id = None

    @staticmethod
    def sanitizeEmail(email_address):
        return email_address.encode('utf-8').strip().lower()

    @staticmethod
    def getHashes(email_address):
        return [
            hashlib.md5(email_address).hexdigest(),
            hashlib.sha1(email_address).hexdigest(),
            hashlib.sha256(email_address).hexdigest()
        ]

    def constructRequestPayload(self, email_address):
        hashes = DSR.getHashes(DSR.sanitizeEmail(email_address))
        request_id = self.request_id or hashes[0]
        # Construct the request payload
        now = datetime.datetime.now()
        payload = { 
            "iss": "CN=" + self.domain_name,
            "aud": self.endpoint,
            "cnf": {
                "kid": self.key_id
            },
            "jti": request_id,
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
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
        with open(self.signing_key) as key_file:
            rsa_key = key_file.read()
        return jwt.encode(payload, rsa_key, algorithm="RS256").decode('utf-8')

    def submitDSRRequest(self, jwt):
        to_send = { "jwt": jwt }
        if(self.verbose):
            print()
            print("Encoded JWT to send" + json.dumps(to_send, indent=2))
        url = self.endpoint + "/dsr"
        return requests.post(url, json=to_send)

    def printHeaders(self, response):
        print("HTTP/1.1 " + str(response.status_code) + " " + response.reason)
        for key,value in response.headers.items():
            print(key + ": " + value)
        print()

    def setAPIEndpoint(self):
        if self.staging:
            self.endpoint = "https://gdpr-test.cph.liveintent.com"
        else:
            self.endpoint = "https://privacy.liadm.com"

        if self.verbose:
            print("Staging=%s, Set API endpoint to %s" % (self.staging, self.endpoint))

    def loadConfig(self, args):
        # Read the config file
        if args.verbose:
            print("Loading configuration from %s" % args.config)
        with open(args.config) as config_json:
            config = json.load(config_json)
        if args.verbose:
            print("Loaded configuration %s" % json.dumps(config, indent=2))
        self.staging = args.staging or config.get("staging", False)
        self.scope = args.scope or config.get("scope", "US_PRIVACY")
        self.callback_url = args.callback_url or config.get("callback_url", None)
        self.verbose = args.verbose
        self.domain_name = config['domain_name']
        self.key_id = config['key_id']
        self.signing_key = config['signing_key']
        self.request_id = args.request_id
        self.setAPIEndpoint()

    def submitEmailRequest(self, email_address):
        payload = self.constructRequestPayload(email_address)
        jwt = self.encodeJWT(payload) 
        response = self.submitDSRRequest(jwt)
        return (payload, response)

    def exec(self, args):
        self.loadConfig(args)
        if args.email_address[0]=="@":
            filename = args.email_address[1:]
            report_name = filename + "." + str(datetime.datetime.now().timestamp()) + ".tsv"
            print(F"Processing email addresses from file {filename}.\nSaving report to {report_name}.")
            with open(report_name,"w") as report:
                print("email_address\trequest_id\tresponse.ok\tresponse.text\ttimestamp", file=report)
                with open(filename, "r") as hashlist:
                    for index,line in enumerate(hashlist):
                        email_address = line.strip()
                        (payload, response) = self.submitEmailRequest(email_address)
                        print(F"{email_address}\t{payload['jti']}\t{response.ok}\t{response.text}\t{payload['iat']}", file=report)
                        print(F"Processing: {email_address}, success={response.ok}")
        else:
            (payload, response) = self.submitEmailRequest(args.email_address)
            if(not response.ok):
                print("ERROR: API call returned an error.")
                print()
                self.printHeaders(response)
            else:
                if(self.verbose):
                    print("Response received")
                    print()
                    self.printHeaders(response)
            print(response.text)

class Delete(DSR):
    def __init__(self, subparsers):
        parser = subparsers.add_parser("delete", \
                help="submits a data delete request for a user.")
        super().__init__(parser, "ERASURE")

class Optout(DSR):
    def __init__(self, subparsers):
        parser = subparsers.add_parser("optout", \
                help="submits an optout request for a user.")
        super().__init__(parser, "OBJECT")

