from __future__ import print_function
import sys
import argparse
import li_privacy
import signal

def signal_handler(sig, frame):
    print('Interrupted by Ctrl+C!')
    sys.exit(0)

def main(name=None):
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(
            description="Interact with the LiveIntent Privacy API", \
            epilog="For API documentation, see https://link.liveintent.com/privacy-api")
    parser.add_argument('--version', action='version', \
            version='%(prog)s v.{version}'.format(version=li_privacy.__version__))
    subparsers = parser.add_subparsers(title="actions", dest='command')
    actions = {
        "init": li_privacy.InitProcessor(subparsers),
        "delete":  li_privacy.DeleteProcessor(subparsers),
        "optout": li_privacy.OptoutProcessor(subparsers)
    }

    args = parser.parse_args(sys.argv[1:])
    try:
        func = actions[args.command]
    except (AttributeError, KeyError):
        parser.print_help()
        return 1
    func.execute(args)

if __name__ == "__main__":
    main()
