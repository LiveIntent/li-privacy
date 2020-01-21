import re
import hashlib

# Small utility class to detect email or hash format and hash
class hash_utility(object):

    # Ugly regex courtesy of https://emailregex.com/
    EMAIL_PATTERN = """(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"""

    # 32, 40, or 64 lower-case hexadecimal characters
    HASH_PATTERN = "^[a-f0-9]{32}([a-f0-9]{8}([a-f0-9]{24})?)?$"

    def hashEmail(self, email_address):
        bytes = email_address.encode('utf-8')
        return [
            hashlib.md5(bytes).hexdigest(),
            hashlib.sha1(bytes).hexdigest(),
            hashlib.sha256(bytes).hexdigest()
        ]

    def getHashes(self, user):
        user = user.strip().lower()
        if re.match(self.HASH_PATTERN, user):
            return [ user ]
        elif re.match(self.EMAIL_PATTERN , user):
            return self.hashEmail(user)
        else:
            raise Exception("Input does not appear to be a valid email or hash")
