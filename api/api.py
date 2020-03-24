"""This module implements the HTTP API endpoint"""

import logging
from urllib import parse
from datetime import datetime
from flask import Flask, request, jsonify
from .auth import Auth
from .autoldap import RoundRobinLdap
from .constants import VLANS, BUILDING_MASK, LOG_LINE, MAC_REGEX, WIFI_VLAN
from .ip import mask_match, mask_extract


app = Flask(__name__)
logging.basicConfig(filename='/var/log/radapi.log', level=logging.DEBUG,
                    format='%(asctime)s -- %(name)s -- %(levelname)s -- %(message)s')
ldap = RoundRobinLdap()


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
    with open("/var/nsa/radius.authentication", "a") as logfile:
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

    if mask_match(ip, *VLANS['sw']):
        vlan = mask_extract(ip, BUILDING_MASK) + 1390
    else:
        vlan = WIFI_VLAN
    if MAC_REGEX.match(user_name):
        logging.debug('MAC Auth for {}'.format(user_name))
        result = Auth.mac(ldap, ip, port, mac, user_name, vlan)
    else:
        logging.debug('802.1x Auth for {}'.format(user_name))
        result = Auth.dot1x(ldap, ip, port, mac, user_name, vlan)
    log(ip, port, mac, user_name, result.get_machine_owner(), result.message, result.auth)
    if result.is_authenticated():
        try:
            result.machine.update_last_date()
        except:
            pass
        code = 200
    else:
        code = 401
    return jsonify(result.get_dict()), code


if __name__ == '__main__':
    logging.basicConfig(filename='/var/log/radapi.log', level=logging.DEBUG,
                        format='%(asctime)s -- %(name)s -- %(levelname)s -- %(message)s')
    ldap = RoundRobinLdap()
    app.run(host='0.0.0.0', port=4000)
