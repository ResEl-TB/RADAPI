(** RADAPI constants *)


let user_regex = Pcre.regexp "^[a-z0-9_-]+$"
let mac_regex = Pcre.regexp "^([a-fA-F0-9]{2})[:.-]?([a-fA-F0-9]{2})[:.-]?([a-fA-F0-9]{2})[:.-]?\
                              ([a-fA-F0-9]{2})[:.-]?([a-fA-F0-9]{2})[:.-]?([a-fA-F0-9]{2})$"


let ldap_servers = Conf.get_string_list "ldap_servers"
let ldap_user = Conf.get_string "ldap_user"
let ldap_password = Conf.get_string "ldap_password"
let device_dn = Conf.get_string "device_dn"
let people_dn = Conf.get_string "people_dn"
let vlans_dn = Conf.get_string "vlans_dn"
let zones_dn = Conf.get_string "zones_dn"

let default_vlan = Conf.get_int "default_vlan"
let subscription_vlan = Conf.get_int "subscription_vlan"

let authorization_log_file = Conf.get_string "authorization_log_file"
let postauth_log_file = Conf.get_string "postauth_log_file"
let accounting_log_file = Conf.get_string "accounting_log_file"

let log_file = Conf.get_string "log_file"
let log_level = Conf.get_string "log_level"

let jobs = Conf.get_int "jobs"
let host = Conf.get_string "host"
let port = Conf.get_int "port"
