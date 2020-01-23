import li_privacy.DSRProcessor as DSRProcessor

class DeleteProcessor(DSRProcessor.DSRProcessor):
    def __init__(self, subparsers):
        parser = subparsers.add_parser("delete", \
                help="submits a data delete request for a user.")
        DSRProcessor.DSRProcessor.__init__(self, parser, "ERASURE")
