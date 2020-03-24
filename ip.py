from constants import MASTER_LDAP, SLAVE_LDAPS
from functools import reduce
from exceptions import NoMoreIPException
from datetime import datetime

class RoundRobinIP:
    def __init__(self):
        self.default_address = MASTER_LDAP
        self.last_crash = datetime.now()
        self.reset(init=True)
        self.next_index = 0

    def next(self):
        n_slaves = len(SLAVE_LDAPS)
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
        self.address = SLAVE_LDAPS[self.index] if not self.is_master else self.default_address
        self.attempts += 1
        return self.address

    def found(self):
        self.attempts = 0

    def reset(self, init=False):
        self.index = 0
        if init or (datetime.now() - self.last_crash).seconds > 300:
            self.is_master = True
            self.address = self.default_address
        self.attempts = 0

    def get(self):
        return self.address

    def get_default(self):
        return self.default_address


def ip2int(ip):
    return reduce(lambda x,y: x*2**8+int(y), ip.split('.'), 0)


def int2ip(i, numbers=4):
    def int2ip_rec(i, numbers):
        if i or numbers > 0:
            return int2ip_rec(i//256, numbers-1) + [str(i%256)]
        return []
    return '.'.join(int2ip_rec(i, numbers))


def mask_match(ip, base, mask):
    return not((ip2int(ip)^ip2int(base)) & ip2int(mask))


def mask_extract(ip, mask):
    imask = ip2int(mask)
    return (ip2int(ip)&imask) // (imask&-imask)
