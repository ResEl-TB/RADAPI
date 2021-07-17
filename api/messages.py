"""This module defines the authentication outcomes"""

from enum import Enum
from .constants import AUTHORIZATION_MESSAGES, POSTAUTH_MESSAGES


class AuthorizationMessage(Enum):
    """This enum defines all the possible outcomes of an authorization"""
    OK = 0
    SUBSCRIPTION_ENDED = 1
    UNKNOWN_USER = 2
    WRONG_AUTH_TYPE = 3
    UNREGISTERED_MACHINE = 4
    INCONSISTENT_MAC = 5
    WRONG_USER = 6
    LDAP_ERROR = 7

    def message(self):
        """
        Return a text message for the current value.
        :return: The authentication result description
        """
        #pylint: disable=E1126
        return AUTHORIZATION_MESSAGES[self.value]


class PostAuthMessage(Enum):
    """This enum defines all the possible outcomes of a post-auth"""
    OK = 0
    LDAP_ERROR = 1

    def message(self):
        """
        Return a text message for the current value.
        :return: The post-auth result description
        """
        #pylint: disable=E1126
        return POSTAUTH_MESSAGES[self.value]
