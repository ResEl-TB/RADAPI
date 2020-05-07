"""This modules provides tools to manipulate IP addresses and pools"""

from datetime import datetime
from functools import reduce
from .exceptions import NoMoreIPException

class RoundRobinIP:
    """
    This class implements a round-robin IP pool
    """
    def __init__(self, master, slaves):
        self.is_master = self.attempts = self.address = self.index = None
        self.default_address = master
        self.slaves = slaves
        self.last_crash = datetime.now()
        self.reset(init=True)
        self.next_index = 0

    def next(self):
        """
        Get the next available IP.
        :returns: The next IP
        """
        n_slaves = len(self.slaves)
        if self.is_master:
            self.last_crash = datetime.now()
        if self.attempts >= n_slaves:
            self.reset()
            raise NoMoreIPException()
        if self.attempts == 0 and not self.is_master:
            self.is_master = True
            self.attempts -= 1
        else:
            self.index = self.next_index
            self.next_index = (self.index + 1) % n_slaves
            self.is_master = False
        self.address = self.slaves[self.index] if not self.is_master else self.default_address
        self.attempts += 1
        return self.address

    def found(self):
        """Reset the internal counter if an IP is reachable"""
        self.attempts = 0

    def reset(self, init=False):
        """
        Reset the internal state.
        :param init: Whether the reinitialization should be forced
        """
        self.index = 0
        if init or (datetime.now() - self.last_crash).seconds > 300:
            self.is_master = True
            self.address = self.default_address
        self.attempts = 0

    def get(self):
        """
        Get the current address
        :returns: The current address
        """
        return self.address

    def get_default(self):
        """
        Get the default/master address
        :returns: The default address
        """
        return self.default_address


def ip2int(ip):
    """
    Convert a string IP to an integer representation
    :param ip: The string IP
    :returns: The integer IP
    """
    return reduce(lambda x, y: x*2**8+int(y), ip.split('.'), 0)


def int2ip(int_ip):
    """
    Convert an integer IP to a string representation
    :param i: The integer IP
    :returns: The string IP
    """
    def int2ip_rec(i, numbers):
        if i or numbers > 0:
            return int2ip_rec(i//256, numbers-1) + [str(i%256)]
        return []
    return '.'.join(int2ip_rec(int_ip, 4))


def mask_match(ip, base, mask):
    """
    Check if an IP matches a mask wrt a base
    :param ip: The ip
    :param base: The base
    :param mask: The mask
    :returns: Whether the IP matches
    """
    return not (ip2int(ip)^ip2int(base)) & ip2int(mask)


def mask_extract(ip, mask):
    """
    Apply a mask to an IP
    :param ip: The ip
    :param mask: The mask
    :returns: The masked IP
    """
    imask = ip2int(mask)
    return (ip2int(ip)&imask) // (imask&-imask)
