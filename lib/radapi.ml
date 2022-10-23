(** This module dispatches RADIUS requests *)


module Log = Dolog.Log


(** Perform a RADIUS authorization
    @param ldap The LDAP connection
    @param ip The NAS IP
    @param port The NAS logical port
    @param user The client UID
    @param mac The client MAC *)
let authorize ldap ip port user mac =
  let module Autz = (val if mac = user then Authorization.(module With (Mac) : Autx.PROCESSOR) else
                                            Authorization.(module With (Dot1x) : Autx.PROCESSOR)) in
  Log.info "Authorizing %s*%s" user mac;
  Autz.process ldap ip port user mac


(** Perform a RADIUS post-authentication
    @param ldap The LDAP connection
    @param ip The NAS IP
    @param port The NAS logical port
    @param user The client UID
    @param mac The client MAC *)
let post_auth ldap ip port user mac =
  let module Auth = (val if mac = user then Post_auth.(module With (Mac) : Autx.PROCESSOR) else
                                            Post_auth.(module With (Dot1x) : Autx.PROCESSOR)) in
  Log.info "Post-authenticating %s*%s" user mac;
  Auth.process ldap ip port user mac


(** Handle a wrong password
    @param ldap The LDAP connection
    @param ip The NAS IP
    @param port The NAS logical port
    @param user The client UID
    @param mac The client MAC *)
let wrong_password ldap ip port user mac =
  let module Wrong_password = Post_auth.With (Post_auth.Wrong_password) in
  Log.info "Wrong password for %s*%s" user mac;
  Wrong_password.process ldap ip port user mac


(** Handle an accounting message
    @param ldap The LDAP connection
    @param status The accounting status
    @param ip The NAS IP
    @param mac The client MAC
    @param timestamp The announced event timestamp
    @param session The session ID *)
let log ldap status ip mac timestamp session =
  Log.info "Accounting for %s/%s" mac ip;
  Accounting.process ldap status ip mac timestamp session
