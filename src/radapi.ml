(** This module is the RADAPI entry point *)


open Lwt.Infix
open Lwt.Syntax
open Opium


module Log = Dolog.Log


let _ldap = ref None
let ldap () = Option.get !_ldap


(** Return a failure response *)
let fail_map timeout reason =
  [("Reply-Message", `String reason); ("Session-Timeout", `Int timeout)]


(** Return a response *)
let data_map vlan timeout password reason =
  fail_map timeout reason @ [("Tunnel-Private-Group-Id", `Int vlan)]
                          @ Radapi__Password.to_map password


(** Give a response to FreeRADIUS *)
let resp f status msg =
  let reason = Radapi__Message.to_string msg in
  Lwt.return @@ Response.of_json ~status ~reason (`Assoc (f reason))


(** Handle authorization requests *)
let handle_autz req =
  let* ip = Request.urlencoded_exn "ip" req
  and* port = Request.urlencoded_exn "port" req
  and* uid = Request.urlencoded_exn "uid" req >|= Radapi__Util.format_user
  and* mac = Request.urlencoded_exn "mac" req >|= Radapi__Util.format_mac in
  (match Radapi.authorize (ldap ()) ip port uid mac with
   | Autz_ok {vlan; remaining; password} as msg ->
       resp (data_map vlan (min remaining 43200) password) `OK msg
   | Subscription_ended {vlan; password; _} as msg -> resp (data_map vlan 3600 password) `OK msg
   | msg -> resp (fail_map 300) `Unauthorized msg)


(** Handle post-authentication requests *)
let handle_auth req =
  let* ip = Request.urlencoded_exn "ip" req
  and* port = Request.urlencoded_exn "port" req
  and* uid = Request.urlencoded_exn "uid" req >|= Radapi__Util.format_user
  and* mac = Request.urlencoded_exn "mac" req >|= Radapi__Util.format_mac in
  Lwt.return (match Radapi.post_auth (ldap ()) ip port uid mac with
   | Auth_ok -> Response.make ~status:`No_content ~reason:"OK" ()
   | msg -> Response.make ~status:`Service_unavailable ~reason:(Radapi__Message.to_string msg) ())


(** Handle wrong passwords *)
let handle_wrong req =
  let* ip = Request.urlencoded_exn "ip" req
  and* port = Request.urlencoded_exn "port" req
  and* uid = Request.urlencoded_exn "uid" req >|= Radapi__Util.format_user
  and* mac = Request.urlencoded_exn "mac" req >|= Radapi__Util.format_mac in
  let msg = Radapi.wrong_password (ldap ()) ip port uid mac in
  Lwt.return @@ Response.make ~status:`Service_unavailable
                              ~reason:(Radapi__Message.to_string msg) ()


(** Get an accounting stat *)
let get_stat name req = Request.urlencoded_exn name req >|= function "" -> 0 | s -> int_of_string s


(** Handle accounting sessions *)
let handle_log req =
  let* status = Request.urlencoded_exn "status" req >|= String.lowercase_ascii
  and* ip = Request.urlencoded_exn "ip" req
  and* mac = Request.urlencoded_exn "mac" req >|= Radapi__Util.format_mac
  and* timestamp = Request.urlencoded_exn "timestamp" req >|= int_of_string
  and* session = Request.urlencoded_exn "session" req
  and* in_packets = get_stat "in-packets" req
  and* out_packets = get_stat "out-packets" req
  and* in_over = get_stat "in-over" req
  and* out_over = get_stat "out-over" req
  and* in_octets = get_stat "in-octets" req
  and* out_octets = get_stat "out-octets" req
  and* reason = Request.urlencoded_exn "reason" req in
  Lwt.async @@ (fun () ->
    Radapi.log (ldap ()) status ip mac timestamp session reason
               (in_packets, out_packets, in_over lsl 32 + in_octets, out_over lsl 32 + out_octets)
    |> Lwt.return);
  Lwt.return @@ Response.make ~status:`No_content ~reason:"Processed" ()


(** Initialize the LDAP connections *)
let init_ldap =
  let filter handler req =
    if Option.is_none !_ldap then _ldap := Some (Radapi__Ldap.init ());
    handler req in
  Rock.Middleware.create ~filter ~name:"Initialize LDAP"


(** Main loop *)
let () =
  let logfile = open_out_gen [Open_wronly; Open_append; Open_creat; Open_text] 0o640
                Radapi__Constants.log_file in
  Lwt_main.at_exit (fun () -> Lwt.return (close_out logfile));
  Log.set_log_level (Log.level_of_string (Radapi__Constants.log_level));
  Log.set_output logfile;

  App.(empty
  |> middleware init_ldap
  |> post "/authorize" handle_autz
  |> post "/post-auth" handle_auth
  |> post "/wrong-password" handle_wrong
  |> post "/log" handle_log
  |> cmd_name "RADAPI"
  |> jobs Radapi__Constants.jobs
  |> host Radapi__Constants.host
  |> port Radapi__Constants.port
  |> run_multicore)
