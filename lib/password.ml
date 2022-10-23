(** This module provides the password model *)


(** Password type *)
type t = Cleartext of string | Hashed of string * string


(** Format a password for FreeRADIUS processing *)
let to_map = function
  | Cleartext s -> [("control:Cleartext-Password", `String s)]
  | Hashed (pw, nt) -> [("control:Password-With-Header", `String pw);
                        ("control:NT-Password", `String ("0x" ^ nt))]
