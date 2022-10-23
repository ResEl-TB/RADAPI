(** Configuration file handler *)


let file = Option.value ~default:"radapi.conf" (Sys.getenv_opt "RADAPI_CONF")
let data = Toml.Parser.(from_filename file |> unsafe)
let get key = try Toml.(Types.Table.find (Min.key key)) data with
  | Not_found -> raise (Failure [%string "%{file}: `%{key}' parameter required but not provided"])
let get_string_list key = match get key with
  | Toml.Types.TArray (NodeString l) -> l
  | TArray NodeEmpty -> []
  | TString s -> [s]
  | _ -> raise (Invalid_argument [%string "%{file}: `%{key}' must be a string or a list thereof"])
let get_string key = match get key with
  | TString s -> s
  | _ -> raise (Invalid_argument [%string "%{file}: `%{key}' must be a string"])
let get_int key = match get key with
  | TInt i -> i
  | _ -> raise (Invalid_argument [%string "%{file}: `%{key}' must be a string"])
