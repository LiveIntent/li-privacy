from .DSRProcessor import DSRProcessor
from .RequestFactory import RequestFactory

class PingProcessor(DSRProcessor):
    def __init__(self):
        DSRProcessor.__init__(self, "PING", False)
        self.description = "submits a ping request to validate keys and connection."

    def construct_request(self):
        return RequestFactory.ping(self.config['domain_name'], self.config['key_id'], self.config.get('callback_url'), self.config.get('request_id'))

    def execute(self, args):
        self._initialize(args)
        request = self.construct_request()
        if self.config["verbose"]:
            print("Request: {}".format(request))
        response = self.api_client.submit(request)
        self.print_response(response)
