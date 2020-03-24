from datetime import datetime
from constants import MACHINE_DN

class User:
    def __init__(self, name, password, nt_password, end_internet):
        self.name = name
        self.password = password
        self.nt_password = nt_password
        self.end_internet = end_internet

    def has_paid(self):
        return datetime.now() < self.end_internet.replace(tzinfo=None)

class Machine:
    def __init__(self, ldap, uid, mac_address, auth_type):
        ldap_result = ldap.get_result()
        self.mac_address = mac_address
        self.auth_type = auth_type
        self.user = User(**ldap.get_user(uid))
        self.ldap = ldap

    def is_mac_auth(self):
        return self.auth_type == 'MAC'

    def is_802_1X_auth(self):
        return self.auth_type == '802.1X'

    def update_last_date(self):
        self.ldap.update('macAddress={},{}'.format(self.mac_address, MACHINE_DN), 'lastDate', datetime.now())
