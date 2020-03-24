"""This module defines the User and Machine models used by the API"""


from datetime import datetime
from .constants import MACHINE_DN

class User:
    """
    This class represents a ResEl user.
    :param name: The user name
    :param password: The user's hashed password
    :param nt_password: The user's NT password
    :param end_internet: The user access expiration
    """
    def __init__(self, name, password, nt_password, end_internet):
        self.name = name
        self.password = password
        self.nt_password = nt_password
        self.end_internet = end_internet

    def has_paid(self):
        """
        Return whether the user has paid their subscription or not.
        :returns: A boolean telling if the user has paid
        """
        return datetime.now() < self.end_internet.replace(tzinfo=None)

class Machine:
    """
    This class represents a ResEl user machine.
    :param ldap: The LDAP to fetch the data from
    :param uid: The user ID
    :param mac_address: The machine MAC
    :param auth_type: The required authentication type
    """
    def __init__(self, ldap, uid, mac_address, auth_type):
        self.mac_address = mac_address
        self.auth_type = auth_type
        self.user = User(**ldap.get_user(uid))
        self.ldap = ldap

    def is_mac_auth(self):
        """
        Return whether the machine should be authenticated with its MAC
        :return: A boolean telling if the machine should use MAC auth
        """
        return self.auth_type == 'MAC'

    def is_802_1x_auth(self):
        """
        Return whether the machine should be authenticated using 802.1x
        :return: A boolean telling if the machine should use 802.1x auth
        """
        return self.auth_type == '802.1X'

    def update_last_date(self):
        """Update the last authentication time in the LDAP"""
        self.ldap.update('macAddress={},{}'.format(self.mac_address, MACHINE_DN), 'lastDate',
                         datetime.now())
