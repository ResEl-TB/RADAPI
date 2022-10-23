(** This module provides the post-authentication logic *)


open Autx
module Log = Dolog.Log


(** Post-authentication functor *)
module With (M : S) = struct
  (** Save the post-authentication result.
      @param ip: The NAS IP
      @param port: The NAS logical port
      @param uid: The client UID
      @param mac: The client MAC
      @param owner: The device owner
      @param message: The authorization message *)
  let log ip port uid mac owner message =
    Util.append_file Constants.postauth_log_file
                     [%string "%{Util.now_us () # Int}// radius.postauth{ip=%{ip},\
                               port=%{Util.percent port},mac=%{mac},uid=%{uid},owner=%{owner},\
                               status=%{Message.to_string message},\
                               auth=%{to_string M.ty}} 1\n"]

  (** Process a post-authentication request
      @param ldap The LDAP connection
      @param ip The NAS IP
      @param port The NAS logical port
      @param uid The client UID
      @param mac The client MAC *)
  let process ldap ip port uid mac =
    let (message, owner) = M.process ldap uid mac in
    log ip port uid mac owner message; message
end


(** MAC post-authentication module *)
module Mac : S = struct
  let ty = Mac

  (** Perform a MAC post-authentication.
      @param ldap The LDAP connection
      @param mac The client's MAC address *)
  let process ldap _ mac =
    let prefix = "[POSTAUTH][with_mac]" in
    match Device.get ldap mac with
      | Ok device ->
          Device.update_date ldap mac;
          Log.info "%s" [%string "%{prefix} (%{mac}) done"];
          (Message.Auth_ok, device.owner_uid)
      | Error Device.Not_found ->
          Log.warn "%s" [%string "%{prefix} (%{mac}) failed: unregistered device"];
          (Message.Unregistered_machine, Owner.unknown)
      | _ -> failwith "Internal error"
end

(** 802.1X post-authentication module *)
module Dot1x : S = struct
  let ty = Dot1x

  (** Perform a post-authentication using 802.1X data.
      @param ldap: The LDAP connection
      @param uid: The user name
      @param mac: The client's MAC address *)
  let process ldap uid mac =
    let prefix = "[POSTAUTH][with_dot1x]" in
    let device = match Device.get ldap mac with
      | Ok device -> device
      | Error (Device.Not_found) ->
          Device.create ldap mac uid;
          Result.get_ok (Device.get ldap mac)
      | _ -> failwith "Internal error" in
    Device.update_date ldap mac;
    Log.info "%s" [%string "%{prefix} (%{mac}) done"];
    (Message.Auth_ok, device.owner_uid)
end

(** Module to handle wrong passwords *)
module Wrong_password : S = struct
  let ty = Dot1x

  (** Handle a wrong password.
      @param ldap: The LDAP connection
      @param mac: The client's MAC address *)
  let process ldap _ mac =
    match Device.get ldap mac with
    | Ok device -> (Message.Wrong_password, device.owner_uid)
    | Error (Device.Not_found) -> (Message.Unregistered_machine, Owner.unknown)
    | _ -> failwith "Internal error"
end
