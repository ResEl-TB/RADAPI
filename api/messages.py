"""This module defines the authentication outcomes"""

from enum import Enum
from .constants import MESSAGES

class Messages(Enum):
    """This enum defines all the possible outcomes of an authentication"""
    AUTH_OK = 0
    SUBSCRIPTION_ENDED = 1
    UNKNOWN_USER = 2
    WRONG_AUTH_TYPE = 3
    UNREGISTERED_DEVICE = 4
    INCONSISTENT_MAC = 5
    WRONG_MACHINE_OWNER = 6
    LDAP_ERROR = 7

    def message(self):
        """
        Return a text message for the current value.
        :return: The authentication result description
        """
        #pylint: disable=E1126
        return MESSAGES[self.value]
