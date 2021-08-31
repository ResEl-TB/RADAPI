"""This module handles wrong passwords"""

from datetime import datetime
from urllib import parse
from .constants import POSTAUTH_LINE, POSTAUTH_LOG_FILE


def log(ip, port, mac, uid):
    """
    Save the post-auth result for a wrong password.
    :param ip: The NAS IP
    :param port: The NAS physical port
    :param mac: The client MAC
    :param uid: The client UID
    """
    with open(POSTAUTH_LOG_FILE, 'a') as logfile:
        logfile.write(POSTAUTH_LINE.format(int(datetime.now().timestamp() * 1000000), ip,
                                           parse.quote(port, safe=''), mac,
                                           parse.quote(uid, safe=''), 'UNKNOWN', 'WRONG_PASSWORD',
                                           '802.1X'))
