(lang dune 3.18)
(name radapi)
(version 3.1.0)
(generate_opam_files true)
(license MIT)
(authors "Benjamin Somers <benjamin.somers@resel.fr>")
(maintainers "Benjamin Somers <benjamin.somers@resel.fr>")
(homepage "https://git.resel.fr/resel/api/radapi")
(source (uri "git+https://git.resel.fr/resel/api/radapi.git"))
(bug_reports "https://git.resel.fr/resel/api/radapi/issues")

(package
 (name radapi)
 (synopsis "RADIUS API")
 (description "This package provides the internal API used by FreeRADIUS within the ResEl")
 (depends
  (alcotest :with-test)
  dolog
  ldap
  ldap-tools
  lwt_ppx
  (opium (>= 0.19.0))
  pcre2
  ppx_catch
  ppx_string
  ppx_map
  timed-cache
  toml
  uri)
 (maintenance_intent "(latest)"))
