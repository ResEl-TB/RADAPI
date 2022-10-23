(** This module defines the Autx outcomes *)


(** Valid Autz type *)
type autz = { vlan: int; remaining: int; password: Password.t }


(** Message type *)
type t = Autz_ok of autz
       | Subscription_ended of autz
       | Auth_ok
       | Wrong_auth_type
       | Unregistered_machine
       | Unknown_user
       | Wrong_user
       | Wrong_password


let to_string = function
  | Autz_ok _ -> "OK"
  | Auth_ok -> "OK"
  | Subscription_ended _ -> "SUBSCRIPTION_ENDED"
  | Wrong_auth_type -> "WRONG_AUTH_TYPE"
  | Unregistered_machine -> "UNREGISTERED_MACHINE"
  | Unknown_user -> "UNKNOWN_USER"
  | Wrong_user -> "WRONG_USER"
  | Wrong_password -> "WRONG_PASSWORD"
