"""This module implements the HTTP API endpoint"""

import logging
from flask import Flask, request, jsonify
from . import authorization, postauth, wrongpassword, accounting
from .ldap import Ldap
from .constants import (MAC_REGEX, LDAP_USER, LDAP_PASSWORD, MASTER_LDAP, SLAVE_LDAPS)


app = Flask(__name__)
logging.basicConfig(filename='/var/log/radapi.log', filemode='a', level=logging.DEBUG,
                    format='%(asctime)s -- %(name)s -- %(levelname)s -- %(message)s')
ldap = Ldap(LDAP_USER, LDAP_PASSWORD, MASTER_LDAP, SLAVE_LDAPS)


@app.route('/authorize', methods=['POST'])
def authorize():
    """This route is the endpoint to authorize the user or device"""
    ip = request.form.get('ip')
    port = request.form.get('port')
    mac = ''.join(request.form.get('mac').split('-')).lower()
    user_name = request.form.get('uid').split('@')[0].lower().strip()

    if MAC_REGEX.match(user_name):
        logging.debug('MAC Authorization for {}'.format(mac))
        result = authorization.with_mac(ldap, mac, user_name)
    else:
        logging.debug('802.1x Authorization for {}*{}'.format(user_name, mac))
        result = authorization.with_dot1x(ldap, mac, user_name)

    authorization.log(ip, port, mac, user_name, result)

    if result.is_authorized():
        logging.debug('-> Redirected to VLAN {}'.format(result.vlan))
        code = 200
    else:
        code = 401

    return jsonify(result.get_dict()), code


@app.route('/post-auth', methods=['POST'])
def post():
    """This route is the endpoint to account for a successful authentication"""
    ip = request.form.get('ip')
    port = request.form.get('port')
    mac = ''.join(request.form.get('mac').split('-')).lower()
    user_name = request.form.get('uid').split('@')[0].lower().strip()

    if MAC_REGEX.match(user_name):
        logging.debug('MAC Post-auth for {}'.format(mac))
        result = postauth.with_mac(ldap, mac, user_name)
    else:
        logging.debug('802.1x Post-auth for {}*{}'.format(user_name, mac))
        result = postauth.with_dot1x(ldap, mac, user_name)

    postauth.log(ip, port, mac, user_name, result)

    if result.is_ok():
        code = 204
    else:
        code = 503

    return jsonify(None), code


@app.route('/wrong-password', methods=['POST'])
def wrong():
    """This route is the endpoint to signal a wrong password entered"""
    ip = request.form.get('ip')
    port = request.form.get('port')
    mac = ''.join(request.form.get('mac').split('-')).lower()
    user_name = request.form.get('uid').split('@')[0].lower().strip()

    logging.debug('Wrong password for {}*{}'.format(user_name, mac))
    wrongpassword.log(ip, port, mac, user_name)

    return jsonify(None), 503


@app.route('/log', methods=['POST'])
def log():
    """This route is the endpoint to log sessions"""
    status = request.form.get('status').lower()
    user_name = request.form.get('uid').split('@')[0].lower().strip()
    ip = request.form.get('ip')
    mac = ''.join(request.form.get('mac').split('-')).lower()
    timestamp = int(request.form.get('timestamp'))
    session = request.form.get('session')
    if status not in ['start', 'interim-update', 'stop']:
        return jsonify(None), 204
    if status == 'start':
        accounting.start(user_name, ip, mac, timestamp, session)
        return jsonify(None), 204
    in_packets = int(request.form.get('in-packets'))
    out_packets = int(request.form.get('out-packets'))
    in_octets = int(request.form.get('in-over')) * 2**32 + int(request.form.get('in-octets'))
    out_octets = int(request.form.get('out-over')) * 2**32 + int(request.form.get('out-octets'))
    if status == 'interim-update':
        accounting.update(user_name, ip, mac, timestamp, session, in_packets, out_packets,
                          in_octets, out_octets)
        return jsonify(None), 204
    reason = request.form.get('reason')
    accounting.stop(user_name, ip, mac, timestamp, session, in_packets, out_packets, in_octets,
                    out_octets, reason)
    return jsonify(None), 204
