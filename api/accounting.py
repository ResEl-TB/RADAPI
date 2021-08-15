"""This module provides the accounting logic"""

import logging
from urllib import parse
from .constants import ACC_START_LINE, ACC_UPDATE_LINE, ACC_STOP_LINE, ACC_LOG_FILE


SESSIONS = {}


def start(uid, ip, mac, timestamp, session):
    """
    Start a session
    :param uid: The client UID
    :param ip: The client IP
    :param mac: The client MAC
    :param timestamp: The announced event timestamp
    :param session: The session ID
    """
    if session in SESSIONS:
        logging.info('[ACCOUNTING][start] Received Start after session started')
        return
    SESSIONS[session] = {'in_packets': 0, 'out_packets': 0, 'in_octets': 0, 'out_octets': 0,
                         'timestamp': timestamp}
    logging.info('[ACCOUNTING][start] {} sessions open'.format(len(SESSIONS)))
    with open(ACC_LOG_FILE, 'a') as logfile:
        logfile.write(ACC_START_LINE.format(int(timestamp * 1000000), parse.quote(uid, safe=''), ip,
                                            mac))


def update(uid, ip, mac, timestamp, session, in_packets, out_packets, in_octets, out_octets):
    """
    Update a session
    :param uid: The client UID
    :param ip: The client IP
    :param mac: The client MAC
    :param timestamp: The announced event timestamp
    :param session: The session ID
    :param in_packets: The amount of IN packets
    :param out_packets: The amount of OUT packets
    :param in_octets: The amount of IN octets
    :param out_octets: The amount of OUT octets
    """
    if session not in SESSIONS:
        logging.info('[ACCOUNTING][update] Received Interim-Update for an unknown session')
        return
    session_data = SESSIONS[session]
    if timestamp <= session_data['timestamp']:
        logging.info('[ACCOUNTING][update] Received an expired Interim-Update')
        return
    deltas = (in_packets - session_data['in_packets'],
              out_packets - session_data['out_packets'],
              in_octets - session_data['in_octets'],
              out_octets - session_data['out_octets'])
    SESSIONS[session] = {'in_packets': in_packets, 'out_packets': out_packets,
                         'in_octets': in_octets, 'out_octets': out_octets, 'timestamp': timestamp}
    with open(ACC_LOG_FILE, 'a') as logfile:
        logfile.write(ACC_UPDATE_LINE.format(int(timestamp * 1000000), parse.quote(uid, safe=''),
                                             ip, mac, *deltas))


def stop(uid, ip, mac, timestamp, session, in_packets, out_packets, in_octets, out_octets, reason):
    """
    Stop a session
    :param uid: The client UID
    :param ip: The client IP
    :param mac: The client MAC
    :param timestamp: The announced event timestamp
    :param session: The session ID
    :param in_packets: The amount of IN packets
    :param out_packets: The amount of OUT packets
    :param in_octets: The amount of IN octets
    :param out_octets: The amount of OUT octets
    :param reason: The stop reason
    """
    if session not in SESSIONS:
        logging.info('[ACCOUNTING][stop] Received Stop for an unknown session')
        return
    session_data = SESSIONS[session]
    if timestamp <= session_data['timestamp']:
        logging.info('[ACCOUNTING][stop] Received an expired Stop')
        return
    deltas = (in_packets - session_data['in_packets'],
              out_packets - session_data['out_packets'],
              in_octets - session_data['in_octets'],
              out_octets - session_data['out_octets'])
    del SESSIONS[session]
    logging.info('[ACCOUNTING][stop] {} sessions remaining'.format(len(SESSIONS)))
    with open(ACC_LOG_FILE, 'a') as logfile:
        logfile.write(ACC_STOP_LINE.format(int(timestamp * 1000000), parse.quote(uid, safe=''),
                                           ip, mac, *deltas, reason))
