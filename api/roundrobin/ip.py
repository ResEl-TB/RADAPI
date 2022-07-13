"""This modules provides tools to manipulate IP addresses and pools"""

from datetime import datetime, timedelta
from functools import reduce
from random import shuffle
from .exceptions import NoMoreIPException


class PoolIP:
    """
    This class implements an IP member of a pool
    """
    def __init__(self, address, should_write):
        self.address = address
        self.should_write = should_write
        self.last_crash = datetime.now()
        self.last_timeout = datetime.now() - timedelta(minutes=10)
        self.up = True

    def reset(self):
        """Reset the state of the IP"""
        self.last_crash = datetime.now()
        self.last_timeout = datetime.now() - timedelta(minutes=10)
        self.up = True

    @property
    def is_available(self):
        """
        Check if the IP is available.
        :returns: Whether the IP is available or not
        """
        if self.up or (datetime.now() - self.last_crash).seconds > 300:
            return True
        return False

    @property
    def can_write(self):
        """
        Check if the IP corresponds to a writable node.
        :returns: Whether the node is writable or not
        """
        return self.should_write and (datetime.now() - self.last_timeout).seconds > 300

    def timed_out(self):
        """Mark the node as timed out"""
        self.last_timeout = datetime.now()


class RoundRobinIP:
    """
    This class implements a round-robin IP pool
    """
    def __init__(self, rw_servers, ro_servers):
        self.servers = ([PoolIP(address, True) for address in rw_servers] +
                        [PoolIP(address, False) for address in ro_servers])
        self.ip = None

    def get_rw_pool(self):
        """
        Get the R/W pool.
        :returns: The R/W pool
        """
        return [srv for srv in self.servers if srv.can_write and srv.is_available]

    def next(self):
        """
        Get the next available IP.
        :returns: The next IP
        """
        self.just_crashed()
        rw_pool = self.get_rw_pool()
        shuffle(rw_pool)
        ro_pool = [srv for srv in self.servers if not srv.can_write and srv.is_available]
        shuffle(ro_pool)
        pool = rw_pool + ro_pool
        try:
            self.ip = pool[0]
            return self.ip.address
        except IndexError as e:
            self.reset()
            raise NoMoreIPException() from e

    def just_crashed(self):
        """Mark the node as just crashed"""
        if self.ip is not None:
            self.ip.last_crash = datetime.now()
            self.ip.up = False

    def reset(self):
        """Reset the internal state"""
        self.ip = None
        for ip in self.servers:
            ip.reset()

    @property
    def address(self):
        """
        Get the node's IP address.
        :returns: The IP address
        """
        return self.ip.address

    @property
    def can_write(self):
        """
        Check if the node has Write capabilities.
        :returns: Whether the node can write
        """
        return self.ip.can_write

    def timed_out(self):
        """Mark the node as timed out"""
        self.ip.timed_out()

    @property
    def has_writable(self):
        """
        Check if the pool has any writable IP.
        :returns: Whether the pool has writable IPs
        """
        return len(self.get_rw_pool()) > 0


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
