(** This module provides the VLAN model *)


[%%attrs objectClass, roomName, zoneID]


open Ldap_tools.Ldap_filter
open Util


(** Subscription VLAN *)
let subscription = Constants.subscription_vlan


(** Get an owner’s VLAN *)
let of_owner ldap Owner.{room_name; _} = match room_name with
  | Some room -> begin
      match Ldap.search ~base:Constants.vlans_dn ldap
                        ((objectClass =^ "reselVLAN") &^ (roomName =^ room)) with
      | entry::_ -> begin
          let data = map_of_entry entry in
          match Ldap.search ~base:Constants.zones_dn ldap
                            ((objectClass =^ "reselZone")
                             &^ (zoneID =^ Str_map.find "zoneid" data)) with
          | entry::_ ->
              let data' = map_of_entry entry in
              Constants.default_vlan + int_of_string (Str_map.find "vlanoffset" data)
                                     + int_of_string (Str_map.find "vlanoffset" data')
          | _ -> Constants.default_vlan end
      | _ -> Constants.default_vlan end
  | None -> Constants.default_vlan
