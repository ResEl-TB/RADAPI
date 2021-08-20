"""This module provides the authorization logic"""

import logging
from binascii import hexlify
from datetime import datetime
from urllib import parse
from .constants import SUBSCRIPTION_VLAN, AUTHORIZATION_LINE, AUTHORIZATION_LOG_FILE
from .exceptions import UserNotFoundException, MachineNotFoundException, NoMoreIPException
from .messages import AuthorizationMessage as Message
from .models import Machine, User


class Result:
    """
    This class represents an authentication result.
    :param auth: The auth type
    :param message: The result message
    :param machine: The client machine object
    :param vlan: The VLAN to redirect the client to
    """
    def __init__(self, auth, message, machine=None, vlan=None):
        self.auth = auth
        self.message = message
        self.machine = machine
        self.vlan = vlan

    def get_machine_owner(self):
        """
        Get the owner of the client machine
        :returns: The owner's UID or 'UNKNOWN'
        """
        try:
            return self.machine.user.name
        except:
            return 'UNKNOWN'

    def is_authorized(self):
        """
        Return whether the client has been authorized or not.
        :returns: A boolean telling if the client is authorized
        """
        return self.message.value <= 1

    def get_timeout(self):
        """
        Get the amount of seconds after which the client must be reauthenticated.
        :returns: The amount of seconds
        """
        if self.message.value == 0:
            return min(43200, int((self.machine.user.end_internet.replace(tzinfo=None) -
                                   datetime.now()).total_seconds()) + 1)
        if self.message.value == 1:
            return 3600
        return 300

    def get_dict(self):
        """
        Get the dictionary to return to FreeRADIUS as a JSON object.
        :returns: The dictionary summarizing the authorization result
        """
        result = {'Reply-Message': self.message.message()}
        result['Session-Timeout'] = self.get_timeout()
        print(self.get_timeout())
        if self.is_authorized():
            user = self.machine.user
            result['Tunnel-Private-Group-Id'] = str(self.vlan)
            if self.auth == 'MAC':
                result['control:Cleartext-Password'] = self.machine.mac_address
            else:
                result['control:NT-Password'] = '0x' + hexlify(user.nt_password.encode('ascii')) \
                                                       .decode('ascii')
                result['control:Password-With-Header'] = user.password
        return result


def with_mac(ldap, mac, user_name):
    """
    Perform a MAC authorization.
    :param ldap: The ldap to connect to
    :param mac: The client's MAC address
    :param user_name: The user name passed by the NAS (should be the same as the MAC address)
    """
    if user_name != mac:
        logging.warning('[AUTHORIZATION][with_mac] ({}) failed: inconsistent MAC'.format(mac))
        return Result('MAC', Message.INCONSISTENT_MAC)

    try:
        machine_data = ldap.get_machine(mac)
        owner = machine_data['uid']
        machine = Machine(ldap, **machine_data)
        if machine.is_mac_auth():
            if machine.user.has_paid():
                logging.info('[AUTHORIZATION][with_mac] ({}*{}) done'.format(owner, mac))
                return Result('MAC', Message.OK, machine,
                              vlan=ldap.get_vlan(machine.user.room_name))
            logging.warning('[AUTHORIZATION][with_mac] ({}*{}) done, but subscription ended'
                            .format(owner, mac))
            return Result('MAC', Message.SUBSCRIPTION_ENDED, machine, vlan=SUBSCRIPTION_VLAN)
        logging.warning('[AUTHORIZATION][with_mac] ({}*{}) failed: wrong auth type'
                        .format(owner, mac))
        return Result('MAC', Message.WRONG_AUTH_TYPE, machine)
    except UserNotFoundException:
        logging.warning('[AUTHORIZATION][with_mac] ({}*{}) failed: unknown owner'
                        .format(owner, mac))
        return Result('MAC', Message.UNKNOWN_USER)
    except MachineNotFoundException:
        logging.warning('[AUTHORIZATION][with_mac] ({}) failed: unregistered device'.format(mac))
        return Result('MAC', Message.UNREGISTERED_MACHINE)
    except NoMoreIPException:
        logging.critical('[AUTHORIZATION][with_mac] ({}) failed: all nodes DOWN'.format(mac))
        return Result('MAC', Message.LDAP_ERROR)


def with_dot1x(ldap, mac, user_name):
    """
    Perform an authorization using 802.1X data.
    :param ldap: The ldap to connect to
    :param mac: The client's MAC address
    :param user_name: The user name
    """
    try:
        user = User(**ldap.get_user(user_name))
        try:
            machine = Machine(ldap, **ldap.get_machine(mac))
            if machine.user.name != user.name:
                logging.warning('[AUTHORIZATION][with_dot1x] ({}*{}) failed: user not owner ({})'
                                .format(user_name, mac, machine.user.name))
                return Result('802.1X', Message.WRONG_USER, machine)
            if not machine.is_802_1x_auth():
                logging.warning('[AUTHORIZATION][with_dot1x] ({}*{}) failed: wrong auth type'
                                .format(user_name, mac))
                return Result('802.1X', Message.WRONG_AUTH_TYPE, machine)
        except MachineNotFoundException:
            logging.info('[AUTHORIZATION][with_dot1x] ({}*{}) needs registration'
                         .format(user_name, mac))
            machine = Machine(ldap, user_name, mac, '802.1X')
        if user.has_paid():
            logging.info('[AUTHORIZATION][with_dot1x] ({}*{}) done'.format(user_name, mac))
            return Result('802.1X', Message.OK, machine, vlan=ldap.get_vlan(user.room_name))
        logging.warning('[AUTHORIZATION][with_dot1x] ({}*{}) done, but subscription ended'
                        .format(user_name, mac))
        return Result('802.1X', Message.SUBSCRIPTION_ENDED, machine, vlan=SUBSCRIPTION_VLAN)
    except UserNotFoundException:
        logging.warning('[AUTHORIZATION][with_dot1x] ({}*{}) failed: unknown user'
                        .format(user_name, mac))
        return Result('802.1X', Message.UNKNOWN_USER)
    except NoMoreIPException:
        logging.critical('[AUTH][with_dot1x] 802.1X Auth ({}*{}) failed: all nodes DOWN'
                         .format(user_name, mac))
        return Result('802.1X', Message.LDAP_ERROR)


def log(ip, port, mac, uid, result):
    """
    Save the authorization result.
    :param ip: The NAS IP
    :param port: The NAS physical port
    :param mac: The client MAC
    :param uid: The client UID
    :param result: The authorization result
    """
    with open(AUTHORIZATION_LOG_FILE, 'a') as logfile:
        logfile.write(AUTHORIZATION_LINE.format(int(datetime.now().timestamp() * 1000000), ip,
                                                parse.quote(port, safe=''), mac,
                                                parse.quote(uid, safe=''),
                                                result.get_machine_owner(), result.message.name,
                                                result.auth))
