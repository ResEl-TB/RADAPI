"""This module defines the tools to communicate with the LDAP"""

import logging
from ldap3 import Server, Connection, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPStrongerAuthRequiredResult
from .exceptions import NoMoreIPException, ReadOnlyException
from .ip import RoundRobinIP


class RoundRobinLdap:
    """This class implements a round-robin LDAP client"""
    def __init__(self, user, password, master, slaves=[]):
        self.user = user
        self.password = password
        self.ip = RoundRobinIP(master, slaves)
        logging.info('[RRLDAP][__init__] Initializing...')
        self.connect(self.ip.get())
        logging.info('[RRLDAP][__init__] Initialized for host {}'.format(self.ip.address))

    def connect(self, address):
        """
        Connect to the LDAP server located at the given address.
        :param address: The LDAP server to connect to
        :returns: Whether the connection has been made
        """
        try:
            logging.info('[RRLDAP][connect] Connecting to {}'.format(address))
            ldap = Connection(Server(address, use_ssl=True, connect_timeout=5), user=self.user,
                              password=self.password, auto_bind=True, return_empty_attributes=True)
            try:
                self.disconnect()
            except:
                pass
            self.ldap = ldap
            self.ip.found()
            logging.info('[RRLDAP][connect] Successful connection to {}'.format(self.ip.address))
        except Exception as e:
            logging.error('[RRLDAP][connect] Connection to {} failed. Reason:\n                  {}'
                          .format(address, e))
            return False
        return True

    def disconnect(self):
        """Disconnect from the currently connected LDAP server, if any"""
        try:
            self.ldap.unbind()
        except:
            pass

    def is_master(self):
        """
        Returns whether the current server is a master node.
        :returns: A boolean telling if the server is master
        """
        return self.ip.is_master

    def do(self, action, *args, **kwargs):
        """
        Execute an action on the LDAP server
        :param action: The action to perform
        :param args: The args to pass
        :param kwargs: The kwargs to pass
        """
        try:
            while True: # As long as possible,
                try:
                    return getattr(self.ldap, action)(*args, **kwargs) # Try to contact the LDAP
                except LDAPStrongerAuthRequiredResult:
                    logging.error('[RRLDAP][do] {} is readonly'.format(self.ip.address))
                    if self.is_master():
                        logging.error('[RRLDAP][do] Master {} is readonly'.format(self.ip.address))
                        raise ReadOnlyException()
                    logging.error('[RRLDAP][do] Node {} is readonly'.format(self.ip.address))
                except Exception as e: # If the current node is down,
                    logging.error('[RRLDAP][do] Connection to {} failed. Reason:\n             {}'
                                  .format(self.ip.address, e))
                #pylint: disable=E1102
                while not self.connect(self.ip.next()): # Find the next available node
                    logging.error('[RRLDAP][do] Connection to {} failed'.format(self.ip.address))
        except NoMoreIPException: # If no node is up,
            logging.critical('[RRLDAP][do] All nodes down')
            raise

    def search(self, query, dn, attributes=[]):
        """
        Perform an LDAP search.
        :param query: The query to execute
        :dn: The base DN
        :attributes: The query attributes
        """
        return self.do('search', dn, query, attributes=attributes)

    def update(self, dn, key, value):
        """
        Update an element in the LDAP server.
        :param dn: The base DN
        :param key: The key to alter
        :param value: The value to set
        """
        try:
            self.do('modify', dn, {key: [(MODIFY_REPLACE, [value])]})
        except ReadOnlyException:
            raise

    def get_result(self):
        """
        Returns the previous query results.
        :returns: The query results
        """
        return self.ldap.entries[0]
