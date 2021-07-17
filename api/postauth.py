"""This module provides the post-auth logic"""

import logging
from datetime import datetime
from urllib import parse
from .constants import POSTAUTH_LINE, POSTAUTH_LOG_FILE
from .models import Machine, User
from .exceptions import MachineNotFoundException, NoMoreIPException, ReadOnlyException
from .messages import PostAuthMessage as Message


class Result:
    """
    This class represents a post-auth result.
    :param message: The result message
    :param machine: The client machine object
    """
    def __init__(self, message, machine=None):
        self.message = message
        self.machine = machine

    def get_machine_owner(self):
        """
        Get the owner of the client machine
        :returns: The owner's UID or 'UNKNOWN'
        """
        try:
            return self.machine.user.name
        except:
            return 'UNKNOWN'

    def is_ok(self):
        """
        Return whether the full authentication is complete or not.
        :returns: A boolean telling if the client is authenticated
        """
        return self.message.value == 0


def process(ldap, mac, user_name):
    """
    Do the required processing.
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
                logging.error('[POSTAUTH][process] ({}*{}) failed: readonly LDAP'
                              .format(user_name, mac))
                return Result(Message.LDAP_ERROR)
        machine = Machine(ldap, **machine_data)
        try:
            result.machine.update_last_date()
        except:
            pass
        return Result(Message.OK, machine)
    except NoMoreIPException:
        logging.critical('[POSTAUTH][process] ({}*{}) failed: all nodes DOWN'
                         .format(user_name, mac))
        return Result(Message.LDAP_ERROR)


def log(ip, port, mac, uid, result):
    """
    Save the post-auth result.
    :param ip: The NAS IP
    :param ip: The NAS physical port
    :param mac: The client MAC
    :param uid: The client UID
    :param result: The post-auth result
    """
    with open(POSTAUTH_LOG_FILE, 'a') as logfile:
        logfile.write(POSTAUTH_LINE.format(int(datetime.now().timestamp() * 1000000), ip,
                                           parse.quote(port, safe=''), mac,
                                           parse.quote(uid, safe=''),
                                           result.get_machine_owner(), result.message.name))
