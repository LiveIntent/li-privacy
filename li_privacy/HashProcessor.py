from __future__ import print_function
import sys
import time
import six
import argparse
import json
import re
from .User import User
from .UserFormatError import UserFormatError

class HashProcessor(object):
    def __init__(self):
        self.description = "Hashes entries from a file"

    def setup_argparse(self, parser):
        parser.add_argument("file", type=str, \
                help="email address or path to file containing email addresses to hash.")
        parser.add_argument("--type", nargs="+", action="store", choices=["md5","sha1","sha256"], required=False, \
                default=[ "md5", "sha1", "sha256" ], help='List of hash algorithms separated by whitespaces (md5 sha1 sha256). Default = md5, sha1, sha256')

    def processLine(self, line, args):
        line = line.strip()
        try:
            user = User(line.strip())
            if(user.user_type=="email"):
                hashes = user.hashes
                if "md5" in args.type:
                    print(hashes[0])
                if "sha1" in args.type:
                    print(hashes[1])
                if "sha256" in args.type:
                    print(hashes[2])
            else:
                print("skipping - " + line, file=sys.stderr)
        except UserFormatError:
            print("skipping - " + line, file=sys.stderr)

    def execute(self, args):
        # Read the config file
        try:
            with open(args.file, "r") as hashlist:
                for line in hashlist:
                    self.processLine(line, args)
        except FileNotFoundError:
            self.processLine(args.file, args)
