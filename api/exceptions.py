"""This module provides all the exceptions needed by the API"""

from .roundrobin import NotFoundException, NoMoreIPException, ReadOnlyException


class UserNotFoundException(NotFoundException):
    """This class represents the fact that a user hasn't been found in the LDAP"""

class MachineNotFoundException(NotFoundException):
    """This class represents the fact that a machine hasn't been found in the LDAP"""
