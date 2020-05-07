"""This module implements the HTTP API endpoint"""

import json
import logging
from urllib import parse
from datetime import datetime
from flask import Flask, request, jsonify
from redis import StrictRedis
from .auth import Auth
from .ldap import Ldap
from .constants import (LOG_LINE, MAC_REGEX, REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, LDAP_USER,
                        LDAP_PASSWORD, MASTER_LDAP, SLAVE_LDAPS)


app = Flask(__name__)
logging.basicConfig(filename='/var/log/radapi.log', filemode='a', level=logging.DEBUG,
                    format='%(asctime)s -- %(name)s -- %(levelname)s -- %(message)s')
ldap = Ldap(LDAP_USER, LDAP_PASSWORD, MASTER_LDAP, SLAVE_LDAPS)
redis_client = StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD)


def log(ip, port, mac, uid, owner, message, auth):
    """
    Save the authentication result.
    :param ip: The NAS IP
    :param ip: The NAS physical port
    :param mac: The client MAC
    :param uid: The client UID
    :param owner: The machine owner
    :param message: The authentication message
    :param auth: The authentication type
    """
    with open('/var/lib/nsa/pending/radius/authentication', 'a') as logfile:
        logfile.write(LOG_LINE.format(int(datetime.now().timestamp() * 1000000), ip,
                                      parse.quote(port, safe=''), mac, parse.quote(uid, safe=''),
                                      owner, message.name, auth))


@app.route('/check', methods=['GET'])
def check():
    """This only route is the endpoint to authenticate the user or device"""
    ip = request.args.get('switch_ip')
    port = request.args.get('switch_port')
    mac = ''.join(request.args.get('client_mac').split('-')).lower()
    user_name = request.args.get('uid').split('@')[0].lower().strip()

    if MAC_REGEX.match(user_name):
        logging.debug('MAC Auth for {}'.format(user_name))
        result = Auth.mac(ldap, mac, user_name)
    else:
        logging.debug('802.1x Auth for {}'.format(user_name))
        result = Auth.dot1x(ldap, mac, user_name)
    log(ip, port, mac, user_name, result.get_machine_owner(), result.message, result.auth)
    if result.is_authenticated():
        try:
            stripped_port = int(port.split('/')[-1])
        except ValueError:
            stripped_port = port
        logging.debug('Redirected to VLAN {}'.format(result.vlan))
        redis_client.rpush('queue:tasks', json.dumps({'task': 'create', 'nas': ip,
                                                      'port': stripped_port, 'vlan': result.vlan}))
        try:
            result.machine.update_last_date()
        except:
            pass
        code = 200
    else:
        code = 401
    return jsonify(result.get_dict()), code
