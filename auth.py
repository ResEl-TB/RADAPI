from binascii import hexlify
from constants import SUBSCRIPTION_VLAN
from datetime import datetime
from exceptions import UserNotFoundException, MachineNotFoundException, NoMoreIPException, ReadOnlyException
from messages import Messages
from models import Machine, User
import logging


class Result:
    def __init__(self, auth, message, machine=None, vlan=None):
        self.auth = auth
        self.message = message
        self.machine = machine
        self.vlan = vlan

    def get_machine_owner(self):
        try:
            return self.machine.user.name
        except:
            return 'UNKNOWN'

    def is_authenticated(self):
        return self.message.value <= 1

    def get_timeout(self):
        if self.message.value == 0:
            return min(43200, int((self.machine.user.end_internet.replace(tzinfo=None) - datetime.now()).total_seconds()) + 1)
        if self.message.value == 1:
            return 3600
        return 300

    def get_dict(self):
        result = {'Reply-Message': self.message.message()}
        result['Session-Timeout'] = self.get_timeout()
        print(self.get_timeout())
        if self.is_authenticated():
            user = self.machine.user
            result['Tunnel-Private-Group-Id'] = str(self.vlan)
            if self.auth == 'MAC':
                result['control:Cleartext-Password'] = self.machine.mac_address
            else:
                result['control:NT-Password'] = '0x' + hexlify(user.nt_password.encode('ascii')).decode('ascii')
                result['control:Password-With-Header'] = user.password
        return result


class Auth:
    @staticmethod
    def mac(ldap, ip, port, mac, user_name, vlan):
        return_vlan = None
        if user_name == mac:
            try:
                machine = Machine(ldap, **ldap.get_machine(mac))
                real_user = machine.user
                if machine.is_mac_auth():
                    if real_user.has_paid():
                        logging.info('[AUTH][mac] MAC Auth ({}) done'.format(user_name))
                        return Result('MAC', Messages.AUTH_OK, machine, vlan)
                    else:
                        logging.warning('[AUTH][mac] MAC Auth ({}) done, but subscription ended'.format(user_name))
                        return Result('MAC', Messages.SUBSCRIPTION_ENDED, machine, SUBSCRIPTION_VLAN)
                else:
                    logging.warning('[AUTH][mac] MAC Auth ({}) failed: wrong auth type for {}'.format(user_name, mac))
                    return Result('MAC', Messages.WRONG_AUTH_TYPE, machine)
            except UserNotFoundException:
                logging.warning('[AUTH][mac] MAC Auth ({}) failed: unknown user'.format(user_name))
                return Result('MAC', Messages.UNKNOWN_USER)
            except MachineNotFoundException:
                logging.warning('[AUTH][mac] MAC Auth ({}) failed: unregistered device {}'.format(user_name, mac))
                return Result('MAC', Messages.UNREGISTERED_DEVICE)
            except NoMoreIPException:
                logging.critical('[AUTH][mac] MAC Auth ({}) failed: all nodes DOWN'.format(user_name))
                return Result('MAC', Messages.LDAP_ERROR)
        else:
            logging.warning('[AUTH][mac] MAC Auth ({}) failed: inconsistent MAC'.format(user_name))
            return Result('MAC', Messages.INCONSISTENT_MAC)

    @staticmethod
    def dot1x(ldap, ip, port, mac, user_name, vlan, again=False):
        try:
            user = User(**ldap.get_user(user_name))
            machine = Machine(ldap, **ldap.get_machine(mac))
            if machine.user.name == user.name:
                if machine.is_802_1X_auth():
                    if user.has_paid():
                        logging.info('[AUTH][dot1x] 802.1X Auth ({}) done'.format(user_name))
                        return Result('802.1X', Messages.AUTH_OK, machine, vlan)
                    else:
                        logging.warning('[AUTH][dot1x] 802.1X Auth ({}) done, but subscription ended'.format(user_name))
                        return Result('802.1X', Messages.SUBSCRIPTION_ENDED, machine, SUBSCRIPTION_VLAN)
                else:
                    logging.warning('[AUTH][dot1x] 802.1X Auth ({}) failed: wrong auth type for {}'.format(user_name, mac))
                    return Result('802.1X', Messages.WRONG_AUTH_TYPE, machine)
            else:
                logging.warning('[AUTH][dot1x] 802.1X Auth ({}) failed: wrong device owner for {} - owner is {}'.format(user_name, mac, machine.user.name))
                return Result('802.1X', Messages.WRONG_MACHINE_OWNER, machine)
        except UserNotFoundException:
            logging.warning('[AUTH][dot1x] 802.1X Auth ({}) failed: unknown user'.format(user_name))
            return Result('802.1X', Messages.UNKNOWN_USER)
        except MachineNotFoundException:
            if again:
                logging.warning('[AUTH][dot1x] 802.1X Auth ({}) failed: unregistered device {} - LDAP Error?'.format(user_name, mac))
                return Result('802.1X', Messages.UNREGISTERED_DEVICE)
            else:
                logging.debug('[AUTH][dot1x] 802.1X Auth ({}) deferred: unregistered device {}'.format(user_name, mac))
                try:
                    ldap.add_machine(mac, user)
                    return Auth.dot1x(ldap, ip, port, mac, user_name, vlan, True)
                except ReadOnlyException:
                    logging.error('[AUTH][dot1x] 802.1X Auth ({}) failed: readonly LDAP'.format(user_name))
                    return Result('802.1X', Messages.LDAP_ERROR)
        except NoMoreIPException:
            logging.critical('[AUTH][dot1x] 802.1X Auth ({}) failed: readonly LDAP'.format(user_name))
            return Result('802.1X', Messages.LDAP_ERROR)
