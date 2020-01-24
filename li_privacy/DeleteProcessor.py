from .DSRProcessor import DSRProcessor
from .RequestFactory import RequestFactory

class DeleteProcessor(DSRProcessor):
    def __init__(self):
        DSRProcessor.__init__(self, "ERASURE", True)
        self.description = "submits a data delete request for a user."

    def construct_request(self, identifiers):
        return RequestFactory.delete(self.config['domain_name'], self.config['key_id'], self.config['scope'], identifiers=identifiers, callback_url=self.config.get('callback_url'), request_id=self.config.get('request_id'))
