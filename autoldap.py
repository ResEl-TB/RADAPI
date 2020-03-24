from ldap3 import Server, Connection, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPStrongerAuthRequiredResult
from constants import LDAP_USER, LDAP_PASSWORD, MASTER_LDAP, SLAVE_LDAPS, UREG, PEOPLE_DN, MACHINE_DN
from exceptions import NoMoreIPException, UserNotFoundException, MachineNotFoundException
from ip import RoundRobinIP
import logging


class RoundRobinLdap:
    def __init__(self):
        self.ip = RoundRobinIP()
        logging.info('[RRLDAP][__init__] Initializing...')
        self.connect(self.ip.get())
        logging.info('[RRLDAP][__init__] Initialized for host {}'.format(self.ip.address))

    def connect(self, address):
        try:
            logging.info('[RRLDAP][connect] Connecting to {}'.format(address))
            ldap = Connection(Server(address, use_ssl=True, connect_timeout=5), user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True, return_empty_attributes=True)
            try:
                self.disconnect()
            except:
                pass
            self.ldap = ldap
            self.ip.found()
            logging.info('[RRLDAP][connect] Successful connection to {}'.format(self.ip.address))
        except Exception as e:
            logging.error('[RRLDAP][connect] Connection to {} failed. Reason:\n                  {}'.format(address, e))
            return False
        return True

    def disconnect(self):
        try:
            self.ldap.unbind()
        except:
            pass

    def do(self, action, *args, **kwargs):
        try:
            while True: # As long as possible,
                try:
                    return getattr(self.ldap, action)(*args, **kwargs) # Try to contact the LDAP
                except LDAPStrongerAuthRequiredResult:
                    logging.error('[RRLDAP][do] {} is readonly'.format(self.ip.address))
                    if self.ip.is_master:
                        logging.error('[RRLDAP][do] Master {} is readonly'.format(self.ip.address))
                        raise ReadOnlyException()
                    else:
                        logging.error('[RRLDAP][do] Node {} is readonly'.format(self.ip.address))
                except Exception as e: # If the current node is down,
                    logging.error('[RRLDAP][do] Connection to {} failed. Reason:\n             {}'.format(self.ip.address, e))
                while not self.connect(self.ip.next()): # Find the next available node
                    logging.error('[RRLDAP][do] Connection to {} failed'.format(self.ip.address))
        except NoMoreIPException: # If no node is up,
            logging.critical('[RRLDAP][do] All nodes down')
            raise

    def search(self, query, dn, attributes=[]):
        return self.do('search', dn, query, attributes=attributes)

    def update(self, dn, key, value):
        try:
            self.do('modify', dn, {key: [(MODIFY_REPLACE, [value])]})
        except ReadOnlyException:
            raise

    def get_user(self, user):
        if not UREG.match(user) or not self.search('(uid={})'.format(user), PEOPLE_DN, ['uid', 'ntPassword', 'userPassword', 'endInternet']):
            raise UserNotFoundException()
        result = self.get_result()
        return {'name': result.uid.value,
                'password': result.userPassword.value.decode('ascii'),
                'nt_password': result.ntPassword.value,
                'end_internet': result.endInternet.value
               }

    def get_machine(self, mac):
        if not self.search('(&(objectclass=reselDevice)(macAddress={}))'.format(mac), MACHINE_DN, ['macAddress', 'authType', 'uidProprio']):
            raise MachineNotFoundException()
        result = self.get_result()
        return {'uid': result.uidProprio.value.split(',')[0].split('=')[1],
                'mac_address': result.macAddress.value,
                'auth_type': result.authType.value
               }

    def get_result(self):
        return self.ldap.entries[0]

    def add_machine(self, mac, user):
        logging.info('[AUTH][add_machine] Adding machine {} for user {}'.format(mac, user.name))
        return self.do('add', 'macAddress={},{}'.format(mac, MACHINE_DN), 'reselDevice', {'authType': '802.1X', 'uidProprio': 'uid={},{}'.format(user.name, PEOPLE_DN)})

