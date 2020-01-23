import li_privacy.DSRProcessor as DSRProcessor

class OptoutProcessor(DSRProcessor.DSRProcessor):
    def __init__(self, subparsers):
        parser = subparsers.add_parser("optout", \
                help="submits an optout request for a user.")
        DSRProcessor.DSRProcessor.__init__(self, parser, "OBJECT")
