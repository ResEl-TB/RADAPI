"""This module provides the post-auth logic"""

import logging
from datetime import datetime
from urllib import parse
from .constants import POSTAUTH_LINE, POSTAUTH_LOG_FILE
from .models import Machine, User, BaseResult
from .exceptions import MachineNotFoundException, NoMoreIPException, ReadOnlyException
from .messages import PostAuthMessage as Message


class Result(BaseResult):
    """This class represents a post-auth result"""

    def is_ok(self):
        """
        Return whether the full authentication is complete or not.
        :returns: A boolean telling if the client is authenticated
        """
        return self.message.value == 0


def with_mac(ldap, mac, user_name):
    """
    Do a MAC post-auth.
    :param ldap: The ldap to connect to
    :param mac: The client's MAC address
    :param user_name: The user name passed by the NAS (should be the same as the MAC address)
    """
    if user_name != mac:
        logging.warning('[POSTAUTH][with_mac] ({}) failed: inconsistent MAC'.format(mac))
        return Result('MAC', Message.INCONSISTENT_MAC)

    try:
        machine_data = ldap.get_machine(mac)
    except MachineNotFoundException:
        logging.error('[POSTAUTH][with_mac] ({}) failed: unregistered device'.format(mac))
        return Result('MAC', Message.UNREGISTERED_MACHINE)
    machine = Machine(ldap, **machine_data)
    try:
        machine.update_last_date()
    except:
        pass
    return Result('MAC', Message.OK, machine)


def with_dot1x(ldap, mac, user_name):
    """
    Do a post-auth using 802.1X data.
    :param ldap: The ldap to connect to
    :param mac: The client's MAC address
    :param user_name: The user name passed by the NAS
    """
    try:
        user = User(**ldap.get_user(user_name))
        machine_data = None
        try:
            machine_data = ldap.get_machine(mac)
        except MachineNotFoundException:
            try:
                ldap.add_machine(mac, user)
                machine_data = ldap.get_machine(mac)
            except ReadOnlyException:
                logging.error('[POSTAUTH][with_dot1x] ({}*{}) failed: readonly LDAP'
                              .format(user_name, mac))
                return Result('802.1X', Message.LDAP_ERROR)
        machine = Machine(ldap, **machine_data)
        try:
            machine.update_last_date()
        except:
            pass
        return Result('802.1X', Message.OK, machine)
    except NoMoreIPException:
        logging.critical('[POSTAUTH][with_dot1x] ({}*{}) failed: all nodes DOWN'
                         .format(user_name, mac))
        return Result('802.1X', Message.LDAP_ERROR)


def wrongpassword(ldap, mac, user_name):
    """
    Do a post-auth with a wrong password.
    :param ldap: The ldap to connect to
    :param mac: The client's MAC address
    :param user_name: The user name passed by the NAS
    """
    machine = None
    try:
        machine_data = ldap.get_machine(mac)
        machine = Machine(ldap, **machine_data)
    except MachineNotFoundException:
        pass
    except NoMoreIPException:
        logging.critical('[WRONGPASSWORD][process] ({}*{}) failed: all nodes DOWN'
                         .format(user_name, mac))
        return Result('802.1X', Message.LDAP_ERROR)
    return Result('802.1X', Message.WRONG_PASSWORD, machine)


def log(ip, port, mac, uid, result):
    """
    Save the post-auth result.
    :param ip: The NAS IP
    :param port: The NAS physical port
    :param mac: The client MAC
    :param uid: The client UID
    :param result: The post-auth result
    """
    with open(POSTAUTH_LOG_FILE, 'a') as logfile:
        logfile.write(POSTAUTH_LINE.format(int(datetime.now().timestamp() * 1000000), ip,
                                           parse.quote(port, safe=''), mac,
                                           parse.quote(uid, safe=''),
                                           result.get_machine_owner(), result.message.name,
                                           result.auth))
