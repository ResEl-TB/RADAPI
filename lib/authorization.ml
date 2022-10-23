(** This module provides the authorization logic *)


open Autx
module Log = Dolog.Log


(** Authorization functor *)
module With (M : S) = struct
  (** Save the authorization result.
      @param ip: The NAS IP
      @param port: The NAS logical port
      @param uid: The client UID
      @param mac: The client MAC
      @param owner: The device owner
      @param message: The authorization message *)
  let log ip port uid mac owner message =
    Util.append_file Constants.authorization_log_file
                     [%string "%{Util.now_us () # Int}// radius.authorization{ip=%{ip},\
                               port=%{Util.percent port},mac=%{mac},uid=%{uid},owner=%{owner},\
                               status=%{Message.to_string message},\
                               auth=%{to_string M.ty}} 1\n"]

  (** Process an authorization request
      @param ldap The LDAP connection
      @param ip The NAS IP
      @param port The NAS logical port
      @param uid The client UID
      @param mac The client MAC *)
  let process ldap ip port uid mac =
    let (message, owner) = M.process ldap uid mac in
    log ip port uid mac owner message; message
end


(** MAC authorization module *)
module Mac : S = struct
  let ty = Mac

  (** Perform a MAC authorization.
      @param ldap The LDAP connection
      @param mac The client's MAC address *)
  let process ldap _ mac =
    let prefix = "[AUTHORIZATION][with_mac]" in
    match Device.get ldap mac >>= ~> (Owner.of_device ldap) with
      | Ok (device, owner) ->
          if device.auth <> ty then
            (Log.warn "%s" [%string "%{prefix} (%{owner.uid}*%{mac}) failed: wrong auth type"];
             Message.Wrong_auth_type, owner.uid) else
          let password = Password.Cleartext mac in
          if Owner.has_paid owner then
            (Log.info "%s" [%string "%{prefix} (%{owner.uid}*%{mac}) done"];
             Message.Autz_ok {remaining = Ldap_tools.Datetime.now_until owner.end_internet;
                              vlan = Vlan.of_owner ldap owner; password}, owner.uid)
          else
            (Log.warn "%s" [%string "%{prefix} (%{owner.uid}*%{mac}) done but subscription ended"];
             Message.Subscription_ended { vlan = Vlan.subscription; remaining = 0; password },
             owner.uid)
      | Error Device.Not_found ->
          Log.warn "%s" [%string "%{prefix} (%{mac}) failed: unregistered device"];
          (Message.Unregistered_machine, Owner.unknown)
      | Error (Owner.Not_found owner_uid) ->
          Log.warn "%s" [%string "%{prefix} (%{owner_uid}*%{mac}) failed: unknown user"];
          (Message.Unknown_user, owner_uid)
      | _ -> failwith "Internal error"
end


(** 802.1X authorization module *)
module Dot1x : S = struct
  let ty = Dot1x

  (** Perform an authorization using 802.1X data.
      @param ldap: The LDAP connection
      @param uid: The user name
      @param mac: The client's MAC address *)
  let process ldap uid mac =
    let prefix = "[AUTHORIZATION][with_dot1x]" in
    let proceed_with owner =
      let password = Password.Hashed (owner.Owner.password, owner.nt_password) in
      if Owner.has_paid owner then
        (Log.info "%s" [%string "%{prefix} (%{uid}*%{mac}) done"];
         Message.Autz_ok {remaining = Ldap_tools.Datetime.now_until owner.end_internet;
                          vlan = Vlan.of_owner ldap owner; password}, uid)
      else
        (Log.warn "%s" [%string "%{prefix} (%{uid}*%{mac}) done but subscription ended"];
         Message.Subscription_ended { vlan = Vlan.subscription; remaining = 0; password }, uid) in
    match Owner.get ldap uid with
    | Ok owner -> begin
        match Device.get ldap mac with
        | Ok device ->
            if device.owner_uid <> uid then
              (Log.info "%s" [%string "%{prefix} (%{uid}*%{mac} failed: user not owner \
                                       (%{device.owner_uid})"];
               Message.Wrong_user, device.owner_uid)
            else if device.auth <> ty then
              (Log.warn "%s" [%string "%{prefix} (%{uid}*%{mac}) failed: wrong auth type"];
               Message.Wrong_auth_type, uid)
            else proceed_with owner
        | Error Device.Not_found ->
            Log.warn "%s" [%string "%{prefix} (%{uid}*%{mac}) needs registration"];
            proceed_with owner
        | _ -> failwith "Internal error"
      end
    | Error (Owner.Not_found owner_uid) ->
        Log.warn "%s" [%string "%{prefix} (%{owner_uid}*%{mac}) failed: unknown user"];
        (Message.Unknown_user, Owner.unknown)
    | _ -> failwith "Internal error"
end
