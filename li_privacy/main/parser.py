"""
THIS SPECIFIC FILE IS DISTRIBUTED UNDER THE UNLICENSE: http://unlicense.org.

THIS MEANS YOU CAN USE THIS CODE EXAMPLE TO KICKSTART A PROJECT YOUR OWN.
AFTER YOU CREATED YOUR OWN ORIGINAL WORK, YOU CAN REPLACE THIS HEADER :)
"""

import sys
import argparse

from .dsr import dsr
from .init import init

def main(name=None):
    """This function is called when run as python3 -m ${MODULE}
    Parse any additional arguments and call required module functions."""

    if sys.argv:
        # called through CLI
        module_name = __loader__.name.split('.')[0]
        parser = argparse.ArgumentParser(
                description="Interact with the LiveIntent Privacy API", \
                epilog="For API documentation, see https://link.liveintent.com/privacy-api", \
                add_help = False
        )
        subparsers = parser.add_subparsers(title="actions", dest='command')

        config_parser = subparsers.add_parser("init", \
                help="sets up the initial configuration")
        config_parser.add_argument("--config", type=str, default="config.json", \
                help="path to configuration file (Defaults to config.json)")
        config_parser.add_argument("--domain_name", type=str, \
                help="your website domain name")
        config_parser.add_argument("--signing_key", type=str, default="rsa256.key", \
                help="path to RSA-256 private signing key file")
        config_parser.add_argument("--key_id", type=str, default="key1", \
                help="the signing key identifier")
        config_parser.set_defaults(func=init().exec)

        delete_parser = subparsers.add_parser("delete", \
                help="submits a data delete request for a user.")
        delete_parser.add_argument("--config", type=str, default="config.json", \
                help="path to configuration file (Defaults to config.json)")
        delete_parser.add_argument("--scope", type=str, \
                choices=["US_PRIVACY","EU_PRIVACY"],  default="US_PRIVACY", \
                help="jurisdiction under which the the request is submitted. (Defaults to US_PRIVACY)")
        delete_parser.add_argument("--callback_url", type=str, \
                help="callback url to be invoked.")
        delete_parser.add_argument("--verbose", "-v", action="store_true", \
                help="enable verbose output")
        delete_parser.add_argument("--staging", action="store_true", \
                help="send to staging environment instead of production.")
        delete_parser.add_argument("email_address", type=str, \
                help="the email address of the user to process")
        delete_parser.set_defaults(func=dsr("ERASURE").exec)


        optout_parser = subparsers.add_parser("optout", \
                parents = [delete_parser], \
                add_help = False, \
                help="submits an optout request for a user.")
        optout_parser.set_defaults(func=dsr("OBJECT").exec)

        args = parser.parse_args(sys.argv[1:])
        try:
            func = args.func
        except AttributeError:
            parser.print_help()
            exit(1)
        func(args)


    return 0
