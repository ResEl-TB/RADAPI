(** This module provides common Autx primitives *)


(** Autx kinds *)
type t = Dot1x | Mac

let of_string = function "802.1X" -> Dot1x | _ -> Mac
let to_string = function Dot1x -> "802.1X" | _ -> "MAC"


(** Autx module signature *)
module type S = sig
  val ty : t
  val process : Ldap.t -> string -> string -> Message.t * string
end


(** Autx functor signature *)
module type PROCESSOR = sig
  val process : Ldap.t -> string -> string -> string -> string -> Message.t
end


(** Monadic operators *)

(** Bind operator *)
let (>>=) = Result.bind

(** “Bind with memory” operator *)
let (~>) f x = f x >>= fun fx -> Ok (x, fx)
