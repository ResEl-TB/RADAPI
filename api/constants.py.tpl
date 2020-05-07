"""This module defines all the constants used by the API"""

import re


BASE_IP = '10.0.0.0'
BUILDING_MASK = '0.0.124.0'
CIDR_17_MASK = '255.31.128.0'
VLANS = {'sw':  ('10.0.0.0', CIDR_17_MASK),
         'ap':  ('10.0.128.0', CIDR_17_MASK)}
MASTER_LDAP = '' # Master IP
SLAVE_LDAPS = [] # Slaves IP list
LDAP_USER = 'cn=admin,dc=maisel,dc=enst-bretagne,dc=fr'
LDAP_PASSWORD = '' # LDAP password
PEOPLE_DN = 'ou=people,dc=maisel,dc=enst-bretagne,dc=fr'
MACHINE_DN = 'ou=devices,dc=resel,dc=enst-bretagne,dc=fr'
VLANS_DN = 'ou=vlans,dc=resel,dc=enst-bretagne,dc=fr'
ZONES_DN = 'ou=zones,dc=resel,dc=enst-bretagne,dc=fr'
UREG = re.compile(r'^[a-zA-Z0-9_-]+$')
MAC_REGEX = re.compile('^[0-9a-f]{12}$')
MESSAGES = ['Auth OK', 'Subscription ended', 'Unknown user', 'Wrong auth type',
            'Unregistered device', 'Inconsistent MAC', 'Wrong machine owner', 'LDAP error']

DEFAULT_VLAN = 2000
SUBSCRIPTION_VLAN = 1311

LOG_LINE = ('{}// radius.authentication'
            '{{ip={},port={},mac={},uid={},real_uid={},status={},auth={}}} 1\n')

REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_PASSWORD = None
