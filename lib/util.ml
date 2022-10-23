(** This module provides utility functions *)


module Str_map = Map.Make (String)


(** Convert an entry into a map.
    @param entry The entry to convert *)
let map_of_entry entry =
  let open Ldap_types in
  let rec map_of_attrs_rec acc = function
    | {attr_type; attr_vals = value::_}::tl ->
        map_of_attrs_rec (Str_map.add (String.lowercase_ascii attr_type) value acc) tl
    | _::tl -> map_of_attrs_rec acc tl
    | [] -> acc in
  map_of_attrs_rec Str_map.empty entry.sr_attributes

(** Convert a map into an entry.
    @param map The map to convert *)
let attrs_of_map map =
  Str_map.fold (fun attr_type value acc -> Ldap_types.{attr_type; attr_vals = [value]}::acc) map []


(** Get the top value of a DN.
    @param dn The DN to process *)
let get_rdn_value dn =
  String.split_on_char ',' dn |> List.hd |> String.split_on_char '=' |> List.tl |> List.hd


(** Preprocess a user name.
    @param user_name The user name *)
let format_user user_name =
  let uid = String.split_on_char '@' user_name |> List.hd |> String.lowercase_ascii in
  assert (Pcre.pmatch ~rex:Constants.user_regex uid); uid


(** Preprocess a MAC address.
    @param mac The MAC address *)
let format_mac mac =
  String.lowercase_ascii mac |> Pcre.exec ~rex:Constants.mac_regex |> Pcre.get_substrings
                             |> Array.to_list |> List.tl |> String.concat ""


(** Percent-encode a string *)
let percent = Uri.pct_encode ~component:`Scheme


(** Get the current epoch time *)
let now () = Ptime.to_float_s (Ptime_clock.now ())


(** Get the current epoch time in microseconds *)
let now_us () =
  int_of_float (now () *. 1000000.)


(** Append to a file.
    @param file The file
    @param data The string to append *)
let append_file file data = (* Should be atomic on our platforms *)
  let out = open_out_gen [Open_wronly; Open_append; Open_creat; Open_text] 0o640 file in
  output_string out data;
  close_out out
