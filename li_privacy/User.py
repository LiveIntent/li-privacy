import re
import hashlib
from .UserFormatError import UserFormatError

class User(object):
    # Ugly regex courtesy of https://emailregex.com/
    EMAIL_PATTERN = """^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"""

    # 32, 40, or 64 lower-case hexadecimal characters
    HASH_PATTERN = "^[a-f0-9]{32}([a-f0-9]{8}([a-f0-9]{24})?)?$"

    def __init__(self, string):
        string = string.strip().lower()
        if re.match(self.EMAIL_PATTERN, string):
            self.user_type = "email"
            self.hashes = self.hash_email(string)
        elif re.match(self.HASH_PATTERN, string):
            self.user_type = "hash"
            self.hashes = [ string ]
        else:
            raise UserFormatError.UserFormatError("Input does not appear to be a valid email or hash")

    def hash_email(self, email_address):
        bytes = email_address.encode('utf-8')
        return [
            hashlib.md5(bytes).hexdigest(),
            hashlib.sha1(bytes).hexdigest(),
            hashlib.sha256(bytes).hexdigest()
        ]

    def json(self):
        return [
                { "type": "EMAIL_HASH", "values": self.hashes }
        ]
