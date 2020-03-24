"""This module provides all the exceptions needed by the API"""

class NoMoreIPException(Exception):
    """This class represents the fact that no more IP is available in the LDAP pool"""

class NotFoundException(Exception):
    """This class is the generic superclass when something hasn't been found"""

class UserNotFoundException(NotFoundException):
    """This class represents the fact that a user hasn't been found in the LDAP"""

class MachineNotFoundException(NotFoundException):
    """This class represents the fact that a machine hasn't been found in the LDAP"""

class ReadOnlyException(Exception):
    """This class represents the fact that the LDAP is read-only"""
