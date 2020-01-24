from .Request import Request

class RequestFactory(object):
    @staticmethod
    def ping(domain_name, key_id, callback_url=None, request_id=None):
        """Factory method to create a new ping request with the specified domain_name, key_id, and optional callback_url and request_id"""
        return Request("PING", "ping", domain_name, key_id, callback_url, identifiers=None, request_id=request_id)

    @staticmethod
    def optout(domain_name, key_id, scope, identifiers, callback_url=None, request_id=None):
        # identifiers is identifiers object
        return Request("OBJECT", "dsr", domain_name, key_id, callback_url, scope, identifiers, request_id=request_id)

    @staticmethod
    def delete(domain_name, key_id, scope, identifiers, callback_url=None, request_id=None):
        # Validate identifiers is object
        return Request("ERASURE", "dsr", domain_name, key_id, callback_url, scope, identifiers, request_id=request_id)

    @staticmethod
    def access(domain_name, key_id, scope, identifiers, callback_url, request_id=None):
        # Validate callback is string
        return Request("ACCESS", "dsr", domain_name, key_id, callback_url, scope, identifiers, request_id=request_id)
