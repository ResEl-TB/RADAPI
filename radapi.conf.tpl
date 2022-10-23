ldap_servers = ["ldaps://10.3.3.1", "ldaps://10.3.3.101"]
ldap_user = "cn=admin,dc=maisel,dc=enst-bretagne,dc=fr"
ldap_password = ""
device_dn = "ou=devices,dc=resel,dc=enst-bretagne,dc=fr"
people_dn = "ou=people,dc=maisel,dc=enst-bretagne,dc=fr"
vlans_dn = "ou=vlans,dc=resel,dc=enst-bretagne,dc=fr"
zones_dn = "ou=zones,dc=resel,dc=enst-bretagne,dc=fr"

default_vlan = 2000
subscription_vlan = 1311

authorization_log_file = "/tmp/authorization"
postauth_log_file = "/tmp/post-auth"
accounting_log_file = "/tmp/accounting"

log_file = "/var/log/radapi.log"
log_level = "debug"
jobs = 1
host = "127.0.0.1"
port = 4000
