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

        example_configuration = config['domain_name']=="dailyplanet.com"
        if example_configuration:
            print("Generating example key and configuration")
            args.config = "dailyplanet.config"
            key_id = config['key_id'] = "key1"
            signing_key = config['signing_key'] = config['domain_name'] + ".key"
            config['staging'] = True
            config['callback_url'] = ""

            # These example keys are only valid in the staging environment which does not execute live transactions
            # therefore they are safe to embed in this source. These keys are also documented in our API guide
            # and are included here for end-user convenience.
            # For obvious reasons, these keys do not work in the production system. :)

            with open(signing_key, "w+") as private_key:
                private_key.write("""-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCXetR4Wz3YxxEZxArubSXHtkACZ9CIPvc7r9AqmfCR4UM+xG5G
7VMU8KRDZrmEaKUzHWVmRSolDIGPFGXjv+csAzBA2aASI4PkxbeYov7xYFD1lQ4k
TTeg+bj0UaivNOChFUHMWwe5I/sVh7wcwIA1kJfQ15lJOgwBfz5fP8URKwIDAQAB
AoGALj0jQD3xygsx8CCEibUtlCHQtitEX2KBC2oma+qjoZQWd8F0PBhThQ/TxHNF
6+IZk1nEywwPylFf9vHuDDBW+wMg9oErNd6C/KlsVaPth/cQxWU5E5IlaANg5rKA
4VbisjXDkc0H/UXc+Dka4CGwfbdHm7ZylCXgYKNtlLtqcRECQQDFqBe6rz/B3vsU
nxyIxPo6BkrVtKhZHoyy+O69qAfy+VpDBnaA3kUWXwvVpvu1QGkdOYMeKJ1j0jYb
2Ayj3tQpAkEAxDFj5RcLnL3dSVORGUBt3uOOqJc+g2JQMZkbElM+9CZMtvOqghWQ
LrLuJKaqADkjnNNrhwRZ+49ivRBnJdwFMwJAVFN6jDLoSJYRGKMpUVB4UPkORE5m
5F6cOF7rvA5MFeU8FQxU0nYBk6HJMsWi7ZklP0qiHePGAihU3Vw3SFJwwQJATKhb
ttyNTf4lo4wCatJw26EgUaFe7KkSWn7PRBbAx1bbrLSCj/dq8cQ6Jpn0XMf2sUUu
g3/gxNkepG7vTqysXwJAE23D11+RZW4hM92TC8zohTw/jgEXR/klWMWykMuidc+M
t1n7m+87k1K1LL11cfK3X4jbdfv0am1EDOtsPIhvzQ==
-----END RSA PRIVATE KEY-----""")
            with open(signing_key + ".pub", "w+") as public_key:
                public_key.write("""-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXetR4Wz3YxxEZxArubSXHtkAC
Z9CIPvc7r9AqmfCR4UM+xG5G7VMU8KRDZrmEaKUzHWVmRSolDIGPFGXjv+csAzBA
2aASI4PkxbeYov7xYFD1lQ4kTTeg+bj0UaivNOChFUHMWwe5I/sVh7wcwIA1kJfQ
15lJOgwBfz5fP8URKwIDAQAB
-----END PUBLIC KEY-----""")
            print("Saved example keys in " + signing_key + " and " + signing_key + ".pub")
            print("To use these example keys, add --config " + args.config + " to your command.")
        else:
            key_id = args.key_id or config.get('key_id','')
            config['key_id'] = input("Key Identifier: (%s) " % key_id) or key_id

            signing_key = args.signing_key or config.get('signing_key', config['domain_name'] + ".key")
            config['signing_key'] = input(F"Path to Private RSA signing key file: ({signing_key}) ") or signing_key

            rsa_key = self.generateKey(config['signing_key'])

        # Write config file
        with open(args.config, "w+") as config_file:
            json.dump(config, config_file, indent=2)
        print(F"Configuration written to {args.config}")
        if not example_configuration:
            self.printProvisioningNotice(args, config)
