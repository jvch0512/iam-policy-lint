let usage = "usage: iam-policy-lint <policy.json or directory> [--html] [--fail-on high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n"

let read_file p = let ic = open_in_bin p in let n = in_channel_length ic in let s = really_input_string ic n in close_in ic; s

let rec collect p =
  if Sys.is_directory p then
    Sys.readdir p |> Array.to_list |> List.sort compare |> List.concat_map (fun f -> collect (Filename.concat p f))
  else if Filename.check_suffix p ".json" then [ p ] else []

let () =
  let args = List.tl (Array.to_list Sys.argv) in
  match args with
  | [] -> prerr_string usage; exit 2
  | path :: rest when String.length path > 0 && path.[0] <> '-' ->
    let html = ref false and fail_on = ref None in
    let rec opts = function
      | [] -> ()
      | "--html" :: t -> html := true; opts t
      | "--fail-on" :: ("high" | "critical" as v) :: t -> fail_on := Some v; opts t
      | o :: _ -> prerr_string ("error: bad option " ^ o ^ "\n" ^ usage); exit 2
    in
    opts rest;
    if not (Sys.file_exists path) then (prerr_string ("error: no such file or directory: " ^ path ^ "\n"); exit 2);
    let base = if Sys.is_directory path then path else Filename.dirname path in
    let rel f = if Sys.is_directory path then String.sub f (String.length base + 1) (String.length f - String.length base - 1) else Filename.basename f in
    let all = List.concat_map (fun f ->
        match Json.parse (read_file f) with
        | doc -> Lint.lint_file ~file:(rel f) doc
        | exception Json.Parse_error m -> prerr_string (Printf.sprintf "error: %s: %s\n" f m); exit 2) (collect path) in
    print_string (if !html then Lint.render_html all else Lint.render_text all);
    let floor = match !fail_on with Some "critical" -> 0 | Some _ -> 1 | None -> -1 in
    if floor >= 0 && List.exists (fun (f : Lint.finding) -> Lint.sev_rank f.severity <= floor) all then exit 1
  | _ -> prerr_string usage; exit 2
