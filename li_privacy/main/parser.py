import sys
import argparse

from .dsr import Delete,Optout
from .init import Init

def main(name=None):
    if sys.argv:
        # called through CLI
        module_name = __loader__.name.split('.')[0]
        parser = argparse.ArgumentParser(
                description="Interact with the LiveIntent Privacy API", \
                epilog="For API documentation, see https://link.liveintent.com/privacy-api", \
                add_help = False
        )
        subparsers = parser.add_subparsers(title="actions", dest='command')
        init_action = Init(subparsers)
        delete_action = Delete(subparsers)
        optout_action = Optout(subparsers)

        args = parser.parse_args(sys.argv[1:])
        try:
            func = args.func
        except AttributeError:
            parser.print_help()
            exit(1)
        func(args)

    return 0
