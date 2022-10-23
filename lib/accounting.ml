(** This module provides the accounting logic *)


module Log = Dolog.Log
module TC = Timed_cache.Make(Timed_cache.Strategy.Synchronous)

let (sessions : (string, unit) TC.t)  = TC.create ~check_every:3600 ~expire_after:86400 200


(** Start an accounting session.
    @param ip The client IP
    @param mac The client MAC
    @param uid The client UID
    @param timestamp The announced event timestamp
    @param session The session ID *)
let start ip mac uid timestamp session =
  if TC.mem sessions session then
    Log.info "%s"
             [%string "[ACCOUNTING][start] (%{uid}*%{mac}): received Start after session started"]
  else begin
    TC.add sessions session ();
    Log.info "%s" [%string "[ACCOUNTING][start] (%{uid}*%{mac}): started; \
                            %{TC.length sessions # Int} sessions now open"];
    let ts = timestamp * 1000000 in
    let common = [%string "owner=%{uid},ip=%{ip},mac=%{mac}"] in
    Util.append_file Constants.accounting_log_file
                     [%string "%{ts # Int}// radius.accounting.summary{type=start,%{common}} 1\n\
                               %{ts # Int}// radius.accounting.packets{direction=in,%{common}} 0\n\
                               %{ts # Int}// radius.accounting.packets{direction=out,%{common}} 0\n\
                               %{ts # Int}// radius.accounting.octets{direction=in,%{common}} 0\n\
                               %{ts # Int}// radius.accounting.octets{direction=out,%{common}} 0\n"]
  end


(** Update an accounting session. The counters are given since session start.
    @param in_packets The number of incoming packets
    @param out_packets The number of outgoing packets
    @param in_octets The number of incoming bytes
    @param out_octets The number of outgoing bytes
    @param ip The client IP
    @param mac The client MAC
    @param uid The client UID
    @param timestamp The announced event timestamp
    @param session The session ID *)
let update (in_packets, out_packets, in_octets, out_octets) ip mac uid timestamp session =
  if TC.mem sessions session then begin
    let ts = timestamp * 1000000 in
    let common = [%string "owner=%{uid},ip=%{ip},mac=%{mac}"] in
    Util.append_file
      Constants.accounting_log_file
      [%string
         "%{ts # Int}// radius.accounting.packets{direction=in,%{common}} %{in_packets # Int}\n\
          %{ts # Int}// radius.accounting.packets{direction=out,%{common}} %{out_packets # Int}\n\
          %{ts # Int}// radius.accounting.octets{direction=in,%{common}} %{in_octets # Int}\n\
          %{ts # Int}// radius.accounting.octets{direction=out,%{common}} %{out_octets # Int}\n"]
  end else
    Log.info "%s" [%string "[ACCOUNTING][update] (%{uid}*%{mac}): received Interim-Update for an \
                            unknown session"]


(** Stop an accounting session. The counters are given since session start.
    @param in_packets The number of incoming packets
    @param out_packets The number of outgoing packets
    @param in_octets The number of incoming bytes
    @param out_octets The number of outgoing bytes
    @param reason The stop reason
    @param ip The client IP
    @param mac The client MAC
    @param uid The client UID
    @param timestamp The announced event timestamp
    @param session The session ID *)
let stop (in_packets, out_packets, in_octets, out_octets) reason ip mac uid timestamp session =
  if TC.mem sessions session then begin
    TC.remove sessions session;
    Log.info "%s" [%string "[ACCOUNTING][update] (%{uid}*%{mac}): stopped; \
                            %{TC.length sessions # Int} sessions are now open"];
    let ts = timestamp * 1000000 in
    let common = [%string "owner=%{uid},ip=%{ip},mac=%{mac}"] in
    Util.append_file
      Constants.accounting_log_file
      [%string
         "%{ts # Int}// radius.accounting.packets{direction=in,%{common}} %{in_packets # Int}\n\
          %{ts # Int}// radius.accounting.packets{direction=out,%{common}} %{out_packets # Int}\n\
          %{ts # Int}// radius.accounting.octets{direction=in,%{common}} %{in_octets # Int}\n\
          %{ts # Int}// radius.accounting.octets{direction=out,%{common}} %{out_octets # Int}\n\
          %{ts # Int}// radius.accounting.summary{type=stop,%{common},reason=%{reason}} 1\n"]
  end else
    Log.info "%s" [%string "[ACCOUNTING][stop] (%{uid}*%{mac}): received Stop for an unknown \
                            session"]


(** Dispatch accounting requests.
    @param ldap The LDAP connection
    @param status The accounting status
    @param ip The client IP
    @param mac The client MAC
    @param timestamp The announced event timestamp
    @param session The session ID
    @param reason The stop reason, if applicable
    @param stats The accounting session stats *)
let process ldap status ip mac timestamp session reason stats =
  let prefix = "[ACCOUNTING][process]" in
  match Device.get ldap mac with
    | Ok device -> (match status with
        | "start" -> start
        | "interim-update" -> update stats
        | "stop" -> stop stats reason
        | _ -> failwith "Wrong accounting method") ip mac device.owner_uid timestamp session
    | Error Device.Not_found ->
        Log.warn "%s" [%string "%{prefix} (%{mac}) failed: unregistered device"]
    | _ -> failwith "Internal error"
