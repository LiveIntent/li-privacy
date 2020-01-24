from __future__ import print_function
import sys
import argparse
import json
import time
import os.path
from .UserFormatError import UserFormatError
from .ApiClient import ApiClient
from .User import User

class DSRProcessor(object):
    def __init__(self, operation, requires_user=True):
        # Setup properties
        self.operation = operation
        self.requires_user = requires_user
        self.config = {}
        self.api_client = None

    def setup_argparse(self, parser):
        parser.add_argument("--config", type=str, default="config.json", \
                help="path to configuration file (Defaults to config.json)")
        parser.add_argument("--scope", type=str, \
                choices=["US_PRIVACY","EU_PRIVACY"], default="US_PRIVACY", \
                help="jurisdiction under which the the request is submitted. (Defaults to US_PRIVACY)")
        parser.add_argument("--callback_url", type=str, \
                help="callback url to be invoked.")
        parser.add_argument("--verbose", "-v", action="store_true", \
                help="enable verbose output")
        parser.add_argument("--staging", action="store_true", \
                help="send to staging environment instead of production.")
        parser.add_argument("--request_id", \
                help="Request ID to be submitted for tracking")
        if self.requires_user:
            parser.add_argument("user", type=str, \
                    help="the email address, hash, or file of users to process")

    def construct_request(self, user):
        """Must be overridden by subclasses"""
        raise Error("Not implemented.")

    def print_headers(self, response):
        print("HTTP/1.1 " + str(response.status_code) + " " + response.reason)
        for key,value in response.headers.items():
            print(key + ": " + value)
        print()

    def print_response(self, response):
        if(not response.ok):
            print("ERROR: API call returned an error.")
            print()
            self.print_headers(response)
        else:
            if self.config['verbose']:
                print("Response received:")
                self.print_headers(response)
                print()
        print(response.text)

    def process_request(self, user):
        request = self.construct_request(user)
        if self.config["verbose"]:
            print("Request: {}".format(request))
        return self.api_client.submit(request)

    def process_file(self, filename):
        report_name = "{}.{}.tsv".format(filename,int(time.strftime("%Y%m%d%H%M%S")))
        print("Processing users from file {}".format(filename))
        with open(report_name,"w") as report:
            print("\t".join([ "user", "request_id", "response.ok", "response.text", "timestamp" ]), file=report)
            with open(filename, "r") as hashlist:
                for line in hashlist:
                    user = User(line.strip())
                    try:
                        response = self.process_request(user)
                        print("\t".join([ user, payload['jti'], response.ok, response.text, payload['iat'] ]), \
                            file=report)
                        print("Processing: {}, success={}".format(user, response.ok))
                    except UserFormatError:
                        print("\t".join([ user, "", "", "Skipped, does not appear to be a valid hash or email", "" ]), \
                            file=report)
                        print("Skipping: '{}', does not appear to be a valid hash or email" \
                            .format(user))
        print("Report saved to {}".format(report_name))

    def process_single(self, user):
        try:
            user = User(user)
            response = self.process_request(user)
            self.print_response(response)
        except UserFormatError:
            print("ERROR: '{}', does not appear to be a valid hash or email" \
                .format(user))

    def _set_overrideable_parameters(self, args):
        # Overridable parameters
        self.config["staging"] = args.staging or self.config.get("staging", False)
        if args.scope:
            self.config["scope"] = args.scope
        if args.callback_url:
            self.config["callback_url"] = args.callback_url
        if args.request_id:
            self.config["request_id"] = args.request_id

    def _load_config(self, args):
        if args.verbose: 
            print("Loading configuration from %s" % args.config)

        # Read the config file
        with open(args.config) as config_json:
            self.config = json.load(config_json)

        self.config['verbose'] = args.verbose
        if self.config['verbose']:
            print("Loaded configuration %s" % json.dumps(self.config, indent=2))

    def _setup_api_client(self, args):
        # Setup api_client with proper environment endpoint
        if self.config['staging']:
            self.config["endpoint"] = "gdpr-test.cph.liveintent.com"
        else: 
            self.config["endpoint"] = "privacy.liadm.com"
        if self.config['verbose']:
            print("Staging=%s, Set API endpoint to %s" % (self.config['staging'], self.config["endpoint"]))

        # Load signing key
        with open(self.config.get("signing_key")) as key_file:
            rsa_key = key_file.read()

        self.api_client = ApiClient(self.config["endpoint"], rsa_key, self.config["verbose"])

    def _initialize(self, args):
        self._load_config(args)
        self._set_overrideable_parameters(args)
        self._setup_api_client(args)

    def execute(self, args):
        self._initialize(args)
        # Test to see if input is file or single
        if os.path.isfile(args.user):
            self.process_file(args.user)
        else:
            self.process_single(args.user)
