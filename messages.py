from enum import Enum
from constants import MESSAGES

class Messages(Enum):
    AUTH_OK = 0
    SUBSCRIPTION_ENDED = 1
    UNKNOWN_USER = 2
    WRONG_AUTH_TYPE = 3
    UNREGISTERED_DEVICE = 4
    INCONSISTENT_MAC = 5
    WRONG_MACHINE_OWNER = 6
    LDAP_ERROR = 7
    def message(self):
        return MESSAGES[self.value]
