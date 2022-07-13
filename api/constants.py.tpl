"""This module defines all the constants used by the API"""

import re


BASE_IP = '10.0.0.0'
BUILDING_MASK = '0.0.124.0'
CIDR_17_MASK = '255.31.128.0'
VLANS = {'sw':  ('10.0.0.0', CIDR_17_MASK),
         'ap':  ('10.0.128.0', CIDR_17_MASK)}
RW_SERVERS = [] # Read/Write LDAP servers
RO_SERVERS = [] # Read-Only LDAP servers
LDAP_USER = 'cn=admin,dc=maisel,dc=enst-bretagne,dc=fr'
LDAP_PASSWORD = '' # LDAP password
PEOPLE_DN = 'ou=people,dc=maisel,dc=enst-bretagne,dc=fr'
MACHINE_DN = 'ou=devices,dc=resel,dc=enst-bretagne,dc=fr'
VLANS_DN = 'ou=vlans,dc=resel,dc=enst-bretagne,dc=fr'
ZONES_DN = 'ou=zones,dc=resel,dc=enst-bretagne,dc=fr'
UREG = re.compile(r'^[a-zA-Z0-9_-]+$')
MAC_REGEX = re.compile('^[0-9a-f]{12}$')
AUTHORIZATION_MESSAGES = ['OK', 'Subscription ended', 'Unknown user', 'Wrong auth type',
                          'Unregistered machine', 'Inconsistent MAC', 'Wrong user', 'LDAP error']
POSTAUTH_MESSAGES = ['OK', 'LDAP error']

DEFAULT_VLAN = 2000
SUBSCRIPTION_VLAN = 1311

AUTHORIZATION_LINE = ('{}// radius.authorization'
                      '{{ip={},port={},mac={},uid={},owner={},status={},auth={}}} 1\n')
AUTHORIZATION_LOG_FILE = '/tmp/authorization'
POSTAUTH_LINE = '{}// radius.postauth{{ip={},port={},mac={},uid={},owner={},status={},auth={}}} 1\n'
POSTAUTH_LOG_FILE = '/tmp/post-auth'
ACC_LOG_FILE = '/tmp/accounting'
ACC_START_LINE = ('{0}// radius.accounting.summary{{type=start,owner={1},ip={2},mac={3}}} 1\n'
                  '{0}// radius.accounting.packets{{direction=in,owner={1},ip={2},mac={3}}} 0\n'
                  '{0}// radius.accounting.packets{{direction=out,owner={1},ip={2},mac={3}}} 0\n'
                  '{0}// radius.accounting.octets{{direction=in,owner={1},ip={2},mac={3}}} 0\n'
                  '{0}// radius.accounting.octets{{direction=out,owner={1},ip={2},mac={3}}} 0\n')
ACC_UPDATE_LINE = ('{0}// radius.accounting.packets{{direction=in,owner={1},ip={2},mac={3}}} {4}\n'
                   '{0}// radius.accounting.packets{{direction=out,owner={1},ip={2},mac={3}}} {5}\n'
                   '{0}// radius.accounting.octets{{direction=in,owner={1},ip={2},mac={3}}} {6}\n'
                   '{0}// radius.accounting.octets{{direction=out,owner={1},ip={2},mac={3}}} {7}\n')
ACC_STOP_LINE = ('{0}// radius.accounting.packets{{direction=in,owner={1},ip={2},mac={3}}} {4}\n'
                 '{0}// radius.accounting.packets{{direction=out,owner={1},ip={2},mac={3}}} {5}\n'
                 '{0}// radius.accounting.octets{{direction=in,owner={1},ip={2},mac={3}}} {6}\n'
                 '{0}// radius.accounting.octets{{direction=out,owner={1},ip={2},mac={3}}} {7}\n'
                 '{0}// radius.accounting.summary{{type=stop,owner={1},ip={2},mac={3},reason={8}}} '
                 '1\n')
