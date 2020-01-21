from __future__ import print_function
import sys
import argparse
import li_privacy.Processor as Processor

def main(name=None):
    parser = argparse.ArgumentParser(
            description="Interact with the LiveIntent Privacy API", \
            epilog="For API documentation, see https://link.liveintent.com/privacy-api")
    subparsers = parser.add_subparsers(title="actions", dest='command')
    actions = {
        "init": Processor.InitProcessor(subparsers),
        "delete":  Processor.DeleteProcessor(subparsers),
        "optout": Processor.OptoutProcessor(subparsers)
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
