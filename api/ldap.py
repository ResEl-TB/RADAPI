"""This module defines the tools used by the API to communicate with the LDAP"""

import logging
from .roundrobin import RoundRobinLdap
from .constants import UREG, PEOPLE_DN, MACHINE_DN, VLANS_DN, ZONES_DN, DEFAULT_VLAN
from .exceptions import MachineNotFoundException, UserNotFoundException


class Ldap(RoundRobinLdap):
    """This class extends the Round-Robin LDAP by adding methods useful for the API"""

    def get_user(self, user):
        """
        Get a user from the LDAP server.
        :param user: The UID of the user to get
        :returns: A dictionary representing the user
        """
        if not UREG.match(user) or not self.search('(uid={})'.format(user), PEOPLE_DN,
                                                   ['uid', 'ntPassword', 'userPassword',
                                                    'endInternet', 'batiment', 'roomNumber']):
            raise UserNotFoundException()
        result = self.get_result()
        return {'name': result.uid.value,
                'password': result.userPassword.value.decode('ascii'),
                'nt_password': result.ntPassword.value,
                'end_internet': result.endInternet.value,
                'room_name': '{}-{:0>3}'.format(result.batiment.value, result.roomNumber.value)
               }

    def get_machine(self, mac):
        """
        Get a user machine from the LDAP server.
        :param mac: The MAC address of the machine to get
        :returns: A dictionary representing the machine
        """
        if not self.search('(&(objectclass=reselDevice)(macAddress={}))'.format(mac), MACHINE_DN,
                           ['macAddress', 'authType', 'uidProprio']):
            raise MachineNotFoundException()
        result = self.get_result()
        return {'uid': result.uidProprio.value.split(',')[0].split('=')[1],
                'mac_address': result.macAddress.value,
                'auth_type': result.authType.value
               }

    def add_machine(self, mac, user):
        """
        Add a machine to the LDAP.
        :param mac: The MAC address
        :param user: The owner
        """
        logging.info('[POSTAUTH][add_machine] Adding machine {} for user {}'.format(mac, user.name))
        return self.do('add', 'macAddress={},{}'.format(mac, MACHINE_DN), 'reselDevice',
                       {'authType': '802.1X', 'uidProprio': 'uid={},{}'.format(user.name,
                                                                               PEOPLE_DN)})

    def get_vlan(self, room_name):
        """
        Get the VLAN associated to the given room.
        :param room_name: The room to consider
        :return: The VLAN or a default VLAN if the room is not found
        """
        if not self.search('(&(objectclass=reselVLAN)(roomName={}))'.format(room_name), VLANS_DN,
                           ['vlanOffset', 'zoneID']):
            return DEFAULT_VLAN
        room = self.get_result()
        if not self.search('(&(objectclass=reselZone)(zoneID={}))'.format(room.zoneID.value),
                           ZONES_DN, ['vlanOffset']):
            return DEFAULT_VLAN
        return DEFAULT_VLAN + int(room.vlanOffset.value) + int(self.get_result().vlanOffset.value)
