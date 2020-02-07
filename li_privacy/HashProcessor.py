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
                help="path to file containing email addresses to hash.")
        parser.add_argument("--type", nargs="+", action="store", choices=["md5","sha1","sha256"], required=False, \
                default=[ "md5" ], help='List of hash algorithms separated by whitespaces (md5 sha1 sha256). Default = md5')
        parser.add_argument("--output", type=str, help="path to the output file")
        parser.add_argument("--verbose", "-v", action="store_true", help="enable verbose output")

    def execute(self, args):
        # Read the config file
        try:
            with open(args.file, "r") as hashlist:
                report_name = args.output or "{}.{}.txt".format(args.file,int(time.strftime("%Y%m%d%H%M%S")))
                if args.verbose:
                    print("Saving output to " + report_name)
                with open(report_name, "w") as report:
                    for line in hashlist:
                        line = line.strip()
                        try:
                            user = User(line.strip())
                            if(user.user_type=="email"):
                                hashes = user.hashes
                                if "md5" in args.type:
                                    print(hashes[0], file=report)
                                if "sha1" in args.type:
                                    print(hashes[1], file=report)
                                if "sha256" in args.type:
                                    print(hashes[2], file=report)
                            else:
                                print("skipping - " + line)
                        except UserFormatError:
                            print("skipping - " + line)
        except FileNotFoundError:
            print("Input file not found")
