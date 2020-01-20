import json
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class Init(object):
    def __init__(self, subparsers):
        config_parser = subparsers.add_parser("init", \
                help="sets up the initial configuration, storing parameters in the config file")
        config_parser.add_argument("--config", type=str, default="config.json", \
                help="path to configuration file (defaults to config.json)")
        config_parser.add_argument("--domain_name", type=str, \
                help="your website domain name")
        config_parser.add_argument("--key_id", type=str, default="key1", \
                help="the signing key identifier")
        config_parser.add_argument("--signing_key", type=str, \
                help="path to RSA-256 private signing key file. Will generate a new key-pair if missing.")
        config_parser.set_defaults(func=self.exec)

    def generateKey(self, signing_key):
        try:
            # Attempt to read existing key
            with open(signing_key) as f:
                private_key = f.read()
            print("Using existing key in " + signing_key)

        except IOError:
            # generate new private/public key pair
            key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, \
                key_size=2048)

            public_key = key.public_key().public_bytes(serialization.Encoding.PEM, \
                serialization.PublicFormat.SubjectPublicKeyInfo)

            pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())

            private_key = pem.decode('utf-8')
            with open(signing_key, "w+") as private_key_file:
                private_key_file.write(private_key)

            public_key = public_key.decode('utf-8')
            with open(signing_key + ".pub", "w+") as public_key_file:
                public_key_file.write(public_key)

            print("Generated new keys in " + signing_key + " and " + signing_key + ".pub")

        return private_key

    def printProvisioningNotice(self, args, config):
        print()
        print("To provision your keys, please email the following files to privacy@liveintent.com:")
        print(F"\t{args.config}")
        print(F"\t{config['signing_key']}.pub")
        print()

    def exec(self, args):
        # Read the config file
        try:
            with open(args.config) as config_json:
                config = json.load(config_json)
            print("Using existing config: %s" % args.config)
        except IOError:
            config = {}
            print("Creating new config: %s" % args.config)
        print()

        domain_name = args.domain_name or config.get('domain_name','')
        while True:
            if domain_name:
                default_prompt = F"({domain_name}) "
            else:
                default_prompt = ""
            config['domain_name'] = input(F"Your website domain name: {default_prompt}") or domain_name
            if not re.match("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", config['domain_name']):
                print("Please enter your website's top-level DNS name only (without http(s)://)")
            else:
                break

        key_id = args.key_id or config.get('key_id','')
        config['key_id'] = input("Key Identifier: (%s) " % key_id) or key_id

        signing_key = args.signing_key or config.get('signing_key', config['domain_name'] + ".key")
        config['signing_key'] = input(F"Path to Private RSA signing key file: ({signing_key}) ") or signing_key

        rsa_key = self.generateKey(config['signing_key'])

        # Write config file
        with open(args.config, "w+") as config_file:
            json.dump(config, config_file, indent=2)
        print(F"Configuration written to {args.config}")
