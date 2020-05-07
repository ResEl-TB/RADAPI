"""This module provides all the exceptions of the roundrobin package"""

class NoMoreIPException(Exception):
    """This class represents the fact that no more IP is available in the LDAP pool"""

class NotFoundException(Exception):
    """This class is the generic superclass when something hasn't been found"""

class ReadOnlyException(Exception):
    """This class represents the fact that the LDAP is read-only"""
