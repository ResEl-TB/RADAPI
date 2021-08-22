"""This module provides the accounting logic"""

import logging
from urllib import parse
from .constants import ACC_START_LINE, ACC_UPDATE_LINE, ACC_STOP_LINE, ACC_LOG_FILE
from .exceptions import MachineNotFoundException


SESSIONS = set()


def start(mac, uid, ip, timestamp, session):
    """
    Start a session
    :param mac: The client MAC
    :param uid: The client UID
    :param ip: The client IP
    :param timestamp: The announced event timestamp
    :param session: The session ID
    """
    if session in SESSIONS:
        logging.info('[ACCOUNTING][start] Received Start after session started')
        return
    SESSIONS.add(session)
    logging.info('[ACCOUNTING][start] {} sessions open'.format(len(SESSIONS)))
    with open(ACC_LOG_FILE, 'a') as logfile:
        logfile.write(ACC_START_LINE.format(int(timestamp * 1000000), parse.quote(uid, safe=''), ip,
                                            mac))


def update(mac, uid, ip, timestamp, session, stats):
    """
    Update a session
    :param mac: The client MAC
    :param uid: The client UID
    :param ip: The client IP
    :param timestamp: The announced event timestamp
    :param session: The session ID
    :param stats: The session stats
    """
    if session not in SESSIONS:
        logging.info('[ACCOUNTING][update] Received Interim-Update for an unknown session')
        return
    with open(ACC_LOG_FILE, 'a') as logfile:
        logfile.write(ACC_UPDATE_LINE.format(int(timestamp * 1000000), parse.quote(uid, safe=''),
                                             ip, mac, *stats))


def stop(mac, uid, ip, timestamp, session, stats, reason):
    """
    Stop a session
    :param uid: The client UID
    :param ip: The client IP
    :param mac: The client MAC
    :param timestamp: The announced event timestamp
    :param session: The session ID
    :param stats: The session stats
    :param reason: The stop reason
    """
    if session not in SESSIONS:
        logging.info('[ACCOUNTING][stop] Received Stop for an unknown session')
        return
    SESSIONS.remove(session)
    logging.info('[ACCOUNTING][stop] {} sessions remaining'.format(len(SESSIONS)))
    with open(ACC_LOG_FILE, 'a') as logfile:
        logfile.write(ACC_STOP_LINE.format(int(timestamp * 1000000), parse.quote(uid, safe=''),
                                           ip, mac, *stats, reason))

def process(ldap, status, mac, *args, **kwargs):
    """
    Route accounting requests
    :param ldap: The LDAP to connect to
    :param status: The accounting status
    :param mac: The client MAC
    """
    try:
        owner = ldap.get_machine(mac)['uid']
    except MachineNotFoundException:
        logging.error('[ACCOUNTING][process] ({}) failed: unregistered device'.format(mac))
        return
    if status == 'start':
        fun = start
    elif status == 'interim-update':
        fun = update
    elif status == 'stop':
        fun = stop
    else:
        return
    fun(mac, owner, *args, **kwargs)
