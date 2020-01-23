from __future__ import print_function
import sys
import argparse
import json
import time
import os.path
import li_privacy.DSR as DSR

class DSRProcessor(object):
    def __init__(self, parser, operation):
        # Setup properties
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
        parser.add_argument("user", type=str, \
                help="the email address, hash, or file of users to process")

    def printHeaders(self, response):
        print("HTTP/1.1 " + str(response.status_code) + " " + response.reason)
        for key,value in response.headers.items():
            print(key + ": " + value)
        print()

    def prepareDSR(self, args):
        # Read the config file
        if args.verbose:
            print("Loading configuration from %s" % args.config)
        with open(args.config) as config_json:
            config = json.load(config_json)
        if args.verbose:
            print("Loaded configuration %s" % json.dumps(config, indent=2))

        # Overridable parameters
        staging = args.staging or config.get("staging", False)

        # Load signing key
        with open(config.get("signing_key")) as key_file:
            rsa_key = key_file.read()

        # Select proper environment
        endpoint = "gdpr-test.cph.liveintent.com" if staging else "privacy.liadm.com"
        if args.verbose:
            print("Staging=%s, Set API endpoint to %s" % (staging, endpoint))

        return DSR.DSR(\
                operation= self.operation, \
                domain_name= config['domain_name'], \
                scope= args.scope or config.get("scope", "US_PRIVACY"), \
                callback_url= args.callback_url or config.get("callback_url", None), \
                key_id= config['key_id'], \
                rsa_key= rsa_key, \
                endpoint= endpoint, \
                verbose= args.verbose
                )

    def processFile(self, args, dsr):
        filename = args.user
        report_name = "{}.{}.tsv".format(filename,int(time.strftime("%Y%m%d%H%M%S")))
        print("Processing users from file {}".format(filename))
        with open(report_name,"w") as report:
            print("user\trequest_id\tresponse.ok\tresponse.text\ttimestamp", file=report)
            with open(filename, "r") as hashlist:
                for line in hashlist:
                    user = line.strip()
                    try:
                        (payload, response) = dsr.submit(user, args.request_id)
                        print("{}\t{}\t{}\t{}\t{}" \
                            .format( \
                            user, payload['jti'], response.ok, response.text, payload['iat']), \
                            file=report)
                        print("Processing: {}, success={}".format(user, response.ok))
                    except:
                        print("{}\t\t\tSkipped, does not appear to be a valid hash or email\t" \
                            .format(user), file=report)
                        print("Skipping: {}, does not appear to be a valid hash or email" \
                            .format(user))
        print("Report saved to {}".format(report_name))

    def processSingle(self, args, dsr):
        (payload, response) = dsr.submit(args.user, args.request_id)
        if(not response.ok):
            print("ERROR: API call returned an error.")
            print()
            self.printHeaders(response)
        else:
            if(args.verbose):
                print("Response received")
                print()
                self.printHeaders(response)
        print(response.text)

    def execute(self, args):
        dsr = self.prepareDSR(args)
        # Test to see if input is file or single
        if os.path.isfile(args.user):
            self.processFile(args, dsr)
        else:
            self.processSingle(args, dsr)
