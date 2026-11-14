(* Minimal strict JSON parser. Standard library only. *)
type t = Null | Bool of bool | Num of float | Str of string | Arr of t list | Obj of (string * t) list

exception Parse_error of string

let parse (s : string) : t =
  let n = String.length s in
  let i = ref 0 in
  let fail m = raise (Parse_error (Printf.sprintf "%s at offset %d" m !i)) in
  let peek () = if !i >= n then fail "unexpected end of input" else s.[!i] in
  let rec ws () = if !i < n && (match s.[!i] with ' ' | '\t' | '\n' | '\r' -> true | _ -> false) then (incr i; ws ()) in
  let string_lit () =
    incr i;
    let b = Buffer.create 16 in
    let rec go () =
      if !i >= n then fail "unterminated string";
      let c = s.[!i] in
      incr i;
      if c = '"' then Buffer.contents b
      else if c = '\\' then begin
        let e = peek () in
        incr i;
        (match e with
         | '"' | '\\' | '/' -> Buffer.add_char b e
         | 'n' -> Buffer.add_char b '\n' | 't' -> Buffer.add_char b '\t' | 'r' -> Buffer.add_char b '\r'
         | 'b' -> Buffer.add_char b '\b' | 'f' -> Buffer.add_char b '\012'
         | 'u' ->
           if !i + 4 > n then fail "bad unicode escape";
           let code = try int_of_string ("0x" ^ String.sub s !i 4) with _ -> fail "bad unicode escape" in
           i := !i + 4;
           if code < 128 then Buffer.add_char b (Char.chr code) else Buffer.add_char b '?'
         | _ -> fail "bad escape");
        go ()
      end else (Buffer.add_char b c; go ())
    in
    go ()
  in
  let rec value depth =
    if depth > 100 then fail "nesting too deep";
    ws ();
    match peek () with
    | '{' ->
      incr i; ws ();
      if peek () = '}' then (incr i; Obj [])
      else begin
        let rec members acc =
          ws ();
          if peek () <> '"' then fail "expected a string key";
          let k = string_lit () in
          ws ();
          if peek () <> ':' then fail "expected ':'";
          incr i;
          let v = value (depth + 1) in
          ws ();
          let c = peek () in
          incr i;
          if c = ',' then members ((k, v) :: acc)
          else if c = '}' then Obj (List.rev ((k, v) :: acc))
          else fail "expected ',' or '}'"
        in
        members []
      end
    | '[' ->
      incr i; ws ();
      if peek () = ']' then (incr i; Arr [])
      else begin
        let rec items acc =
          let v = value (depth + 1) in
          ws ();
          let c = peek () in
          incr i;
          if c = ',' then items (v :: acc)
          else if c = ']' then Arr (List.rev (v :: acc))
          else fail "expected ',' or ']'"
        in
        items []
      end
    | '"' -> Str (string_lit ())
    | 't' when !i + 4 <= n && String.sub s !i 4 = "true" -> i := !i + 4; Bool true
    | 'f' when !i + 5 <= n && String.sub s !i 5 = "false" -> i := !i + 5; Bool false
    | 'n' when !i + 4 <= n && String.sub s !i 4 = "null" -> i := !i + 4; Null
    | c when c = '-' || (c >= '0' && c <= '9') ->
      let st = !i in
      while !i < n && (match s.[!i] with '0' .. '9' | '-' | '+' | '.' | 'e' | 'E' -> true | _ -> false) do incr i done;
      (try Num (float_of_string (String.sub s st (!i - st))) with _ -> fail "bad number")
    | c -> fail (Printf.sprintf "unexpected character '%c'" c)
  in
  let v = value 0 in
  ws ();
  if !i <> n then fail "trailing data";
  v

let member k = function Obj l -> (try Some (List.assoc k l) with Not_found -> None) | _ -> None
let to_strings = function Str s -> [ s ] | Arr l -> List.filter_map (function Str s -> Some s | _ -> None) l | _ -> []
