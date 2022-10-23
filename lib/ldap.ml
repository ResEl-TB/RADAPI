(** This module provides wrappers to communicate with an LDAP server *)


module Log = Dolog.Log
module TC = Timed_cache.Make(Timed_cache.Strategy.Synchronous)


(** Type for LDAP connections *)
type t = Ldap_ooclient.ldapcon_t


(** Perform a direct LDAP search *)
let _search ((ldap:t), base, filter) =
  Log.debug "Searching %s in %s" filter base;
  List.map Ldap_ooclient.of_entry (ldap#search ~base filter)

(** Perform a cached LDAP search *)
let _cached_search = TC.wrap' ~check_every:10 ~expire_after:60 _search
                              ~transform:(fun (_, _, filter) -> filter)
                              ~accept:(fun _ -> function [] -> false | _ -> true)

(** Perform an LDAP search.
    @param base The base DN
    @param ldap The LDAP connection
    @param filter The search filter *)
let search ~base ldap filter = _cached_search (ldap, base, filter)


(** Perform an LDAP modification.
    @param ldap The LDAP connection
    @param dn The DN to modify
    @param mods The modifications to perform *)
let modify ldap ~dn ~mods = ldap#modify dn mods


(** Perform an LDAP add operation.
    @param ldap The LDAP connection
    @param entry The entry to add *)
let add ldap entry = ldap#add (Ldap_ooclient.to_entry (`Entry entry))


(** Initialize the LDAP connection *)
let init () =
  Log.info "Initializing an LDAP connection";
  let conn = new Ldap_ooclient.ldapcon ~timeout:0.5 Constants.ldap_servers in
  let timer = ref 0. in
  (* Add a hook on the modification operation if the LDAP server cannot be written to *)
  conn#hook `MODIFY (Some (fun f ->
    let now = Util.now () in
    if now -. !timer < 300. then Log.warn "Skipping this write operation"
    else try f () with Ldap_types.LDAP_Failure _ ->
      Log.warn "Could not write to the LDAP server";
      conn#unbind;
      timer := now));
  conn#bind ~cred:Constants.ldap_password Constants.ldap_user;
  conn
