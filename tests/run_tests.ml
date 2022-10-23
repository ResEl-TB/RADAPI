(** This module tests the API with Alcotest *)

open Alcotest

let ldap = Radapi__Ldap.init ()

let check_autz value user mac =
  check string value value (Radapi__Message.to_string (Radapi.authorize ldap "127.0.0.1" "" user mac))

let test_autz_ok () =
  check_autz "OK" "testuser-valid" "0200fff00101";
  check_autz "OK" "0200fff00102" "0200fff00102"

let test_autz_subscription_ended () =
  check_autz "SUBSCRIPTION_ENDED" "testuser-expired" "0200fff00001";
  check_autz "SUBSCRIPTION_ENDED" "0200fff00002" "0200fff00002"

let test_autz_wrong_auth_type () =
  check_autz "WRONG_AUTH_TYPE" "0200fff00001" "0200fff00001";
  check_autz "WRONG_AUTH_TYPE" "testuser-expired" "0200fff00002";
  check_autz "WRONG_AUTH_TYPE" "0200fff00101" "0200fff00101";
  check_autz "WRONG_AUTH_TYPE" "testuser-valid" "0200fff00102"

let test_autz_unregistered_machine () =
  check_autz "UNREGISTERED_MACHINE" "0200fff00003" "0200fff00003";
  check_autz "SUBSCRIPTION_ENDED" "testuser-expired" "0200fff00003";
  check_autz "UNREGISTERED_MACHINE" "0200fff00103" "0200fff00103";
  check_autz "OK" "testuser-valid" "0200fff00103"

let test_autz_unknown_user () =
  check_autz "UNKNOWN_USER" "testuser-unknown" "0200fff00001"

let test_autz_wrong_user () =
  check_autz "WRONG_USER" "testuser-expired" "0200fff00101";
  check_autz "WRONG_USER" "testuser-valid" "0200fff00001"

let autz_tests = [
  ("OK", `Quick, test_autz_ok);
  ("SUBSCRIPTION_ENDED", `Quick, test_autz_subscription_ended);
  ("WRONG_AUTH_TYPE", `Quick, test_autz_wrong_auth_type);
  ("UNREGISTERED_MACHINE", `Quick, test_autz_unregistered_machine);
  ("UNKNOWN_USER", `Quick, test_autz_unknown_user);
  ("WRONG_USER", `Quick, test_autz_wrong_user);
]

let check_auth value user mac =
  check string value value (Radapi__Message.to_string (Radapi.post_auth ldap "127.0.0.1" "" user mac))

let test_auth_ok () =
  check_auth "OK" "testuser-valid" "0200fff00101";
  check_auth "OK" "0200fff00102" "0200fff00102"

let test_auth_unregistered_machine () =
  check_auth "UNREGISTERED_MACHINE" "0200fff00003" "0200fff00003";
  check_auth "OK" "testuser-expired" "0200fff00003";
  check_auth "UNREGISTERED_MACHINE" "0200fff00103" "0200fff00103";
  check_auth "OK" "testuser-valid" "0200fff00103"

let auth_tests = [
  ("OK", `Quick, test_auth_ok);
  ("UNREGISTERED_MACHINE", `Quick, test_auth_unregistered_machine);
]

let test_suites: unit test list = [
  "Authorization", autz_tests;
  "Post-auth", auth_tests;
]

let delete conn dn =
  try Ldap_funclient.delete_s conn ~dn with
  | Ldap_types.LDAP_Failure (`NO_SUCH_OBJECT, _, _) -> ()

(** Run the test suites *)
let () =
  let module Constants = Radapi__Constants in
  let conn = Ldap_funclient.init Constants.ldap_servers in
  Ldap_funclient.bind_s ~who:Constants.ldap_user ~cred:Constants.ldap_password conn;
  delete conn ("macAddress=0200fff00003," ^ Constants.device_dn);
  delete conn ("macAddress=0200fff00103," ^ Constants.device_dn);
  run "RADAPI" test_suites
