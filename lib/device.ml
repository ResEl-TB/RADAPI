(** This module provides the device model *)


[%%attrs objectClass, macAddress]


open Util
open Ldap_tools.Ldap_filter


(** Device type *)
type t = {owner_uid: string; auth: Autx.t}

(** Extension of the error variant *)
type Error.t += Not_found


(** Get a device from the LDAP.
    @param ldap The LDAP connection
    @param mac The device MAC address *)
let get ldap mac =
  match Ldap.search ~base:Constants.device_dn ldap
                    ((objectClass =^ "reselDevice") &^ (macAddress =^ mac)) with
  | entry::_ ->
      let data = map_of_entry entry in
      Ok (Str_map.{owner_uid = get_rdn_value (find "uidproprio" data);
                   auth = Autx.of_string (find "authtype" data)})
  | _ -> Error Not_found


(** Update a device “last seen” date in the LDAP.
    @param ldap The LDAP connection
    @param mac The device MAC address *)
let update_date ldap mac =
  Ldap.modify ldap ~dn:[%string "macAddress=%{mac},%{Constants.device_dn}"]
              ~mods:[(`REPLACE, "lastDate", [Ldap_tools.Datetime.now ()])]


(** Create a device in the LDAP.
    @param ldap The LDAP connection
    @param mac The device MAC address
    @param uid The device owner *)
let create ldap mac uid =
  let attrs = attrs_of_map [%map "objectClass" => "reselDevice"; "authType" => "802.1X";
                                 "uidProprio" => [%string "uid=%{uid},%{Constants.people_dn}"]] in
  Ldap.add ldap Ldap_types.{sr_dn = [%string "macAddress=%{mac},%{Constants.device_dn}"];
                            sr_attributes = attrs}
