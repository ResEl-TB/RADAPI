(** This module provides the owner model *)


[%%attrs uid]


open Util
open Ldap_tools.Ldap_filter


(** Owner type *)
type t = {uid: string; password: string; nt_password: string; end_internet: string;
          room_name: string option}

(** Extension of the error variant *)
type Error.t += Not_found of string


let unknown = "UNKNOWN"


(** Format a room name, if able.
    @param building The room building
    @param room The room number *)
let format_room building room =
  [%catch.o
    let b = Option.get building in
    let r = Option.get room in
    Printf.sprintf "%s-%03i" b (int_of_string r)]


(** Check if the owner is up to date with their subscription *)
let has_paid {end_internet; _} = Ldap_tools.Datetime.is_future end_internet


(** Get an owner from the LDAP.
    @param ldap The LDAP connection
    @param owner_uid The owner uid *)
let get ldap owner_uid =
  match Ldap.search ~base:Constants.people_dn ldap (uid =^ owner_uid) with
  | entry::_ ->
      let data = map_of_entry entry in
      Ok (Str_map.{uid = owner_uid;
                   password = find "userpassword" data;
                   nt_password = find "ntpassword" data;
                   end_internet = find "endinternet" data;
                   room_name = format_room (find_opt "batiment" data)
                                           (find_opt "roomnumber" data)})
  | _ -> Error (Not_found owner_uid)


(** Get a device owner from the LDAP *)
let of_device ldap Device.{owner_uid; _} = get ldap owner_uid
