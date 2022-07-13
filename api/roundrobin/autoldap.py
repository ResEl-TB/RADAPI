"""This module defines the tools to communicate with the LDAP"""

import logging
from ldap3 import Server, Connection, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPStrongerAuthRequiredResult, LDAPUnavailableResult
from .exceptions import NoMoreIPException, ReadOnlyException
from .ip import RoundRobinIP
#from ldap3.utils.log import set_library_log_detail_level, NETWORK
#set_library_log_detail_level(NETWORK)


class RoundRobinLdap:
    """This class implements a round-robin LDAP client"""
    def __init__(self, user, password, rw_servers=None, ro_servers=None):
        self.user = user
        self.password = password
        self.ip = RoundRobinIP(rw_servers, ro_servers)
        self.ldap = None

    def connect(self, address):
        """
        Connect to the LDAP server located at the given address.
        :param address: The LDAP server to connect to
        :returns: Whether the connection has been made
        """
        try:
            logging.info('[RRLDAP][connect] Connecting to {}'.format(address))
            ldap = Connection(Server(address, use_ssl=True, connect_timeout=5), user=self.user,
                              password=self.password, auto_bind=True, return_empty_attributes=True,
                              raise_exceptions=True, receive_timeout=20)
            self.disconnect()
            self.ldap = ldap
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

    @property
    def can_write(self):
        """
        Returns whether the current server is a R/W node.
        :returns: A boolean telling if the server is R/W
        """
        return self.ip.can_write

    def raise_ro_fast(self):
        """Raises a ReadOnlyException if there is no R/W IP in the pool"""
        if not self.ip.has_writable:
            raise ReadOnlyException()

    def timed_out(self):
        """Indicates that the server timed out"""
        self.ip.timed_out()

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
                except (LDAPStrongerAuthRequiredResult, LDAPUnavailableResult) as e:
                    if self.can_write:
                        self.timed_out()
                        logging.error('[RRLDAP][do] R/W node {} is R/O'.format(self.ip.address))
                        raise ReadOnlyException() from e
                    logging.error('[RRLDAP][do] {} is R/O'.format(self.ip.address))
                except AttributeError:
                    pass
                except Exception as e: # If the current node is down,
                    logging.error('[RRLDAP][do] Connection to {} failed. Reason:\n             {}'
                                  .format(self.ip.address, e))
                #pylint: disable=E1102
                while not self.connect(self.ip.next()): # Find the next available node
                    logging.error('[RRLDAP][do] Connection to {} failed'.format(self.ip.address))
        except NoMoreIPException: # If no node is up,
            self.disconnect()
            self.ldap = None
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
        self.raise_ro_fast()
        self.do('modify', dn, {key: [(MODIFY_REPLACE, [value])]})

    def get_result(self):
        """
        Returns the previous query results.
        :returns: The query results
        """
        return self.ldap.entries[0]
