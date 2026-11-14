(* IAM policy rules. Standard library only. *)
type severity = Critical | High | Medium

let sev_name = function Critical -> "critical" | High -> "high" | Medium -> "medium"
let sev_rank = function Critical -> 0 | High -> 1 | Medium -> 2

type finding = { file : string; stmt : string; rule : string; severity : severity; message : string }

(* glob match with '*' and '?', case-insensitive: IAM actions are case-insensitive *)
let glob pat s =
  let p = String.lowercase_ascii pat and s = String.lowercase_ascii s in
  let np = String.length p and ns = String.length s in
  let rec go i j =
    if i = np then j = ns
    else match p.[i] with
      | '*' -> go (i + 1) j || (j < ns && go i (j + 1))
      | '?' -> j < ns && go (i + 1) (j + 1)
      | c -> j < ns && s.[j] = c && go (i + 1) (j + 1)
  in
  go 0 0

let escalation = [
  "iam:CreatePolicyVersion"; "iam:SetDefaultPolicyVersion"; "iam:AttachUserPolicy"; "iam:AttachGroupPolicy";
  "iam:AttachRolePolicy"; "iam:PutUserPolicy"; "iam:PutGroupPolicy"; "iam:PutRolePolicy"; "iam:CreateAccessKey";
  "iam:CreateLoginProfile"; "iam:UpdateLoginProfile"; "iam:UpdateAssumeRolePolicy"; "iam:AddUserToGroup";
]

let sensitive_on_star = [ "iam:PassRole"; "sts:AssumeRole"; "kms:Decrypt"; "secretsmanager:GetSecretValue"; "ssm:GetParameter*"; "s3:GetObject"; "lambda:UpdateFunctionCode"; "ec2:RunInstances" ]

let statements doc =
  match Json.member "Statement" doc with
  | Some (Json.Arr l) -> l
  | Some (Json.Obj _ as o) -> [ o ]
  | _ -> []

let lint ~file (doc : Json.t) : finding list =
  let out = ref [] in
  let add stmt rule severity message = out := { file; stmt; rule; severity; message } :: !out in
  (match Json.member "Version" doc with
   | Some (Json.Str "2012-10-17") -> ()
   | _ -> add "(policy)" "IAM008" Medium "missing or old Version: use 2012-10-17, or policy variables are not evaluated");
  List.iteri
    (fun idx st ->
       let sid = match Json.member "Sid" st with Some (Json.Str s) -> s | _ -> Printf.sprintf "#%d" (idx + 1) in
       let allow = (match Json.member "Effect" st with Some (Json.Str "Allow") -> true | _ -> false) in
       let get k = match Json.member k st with Some v -> Json.to_strings v | None -> [] in
       let actions = get "Action" and resources = get "Resource" in
       let has_cond = (match Json.member "Condition" st with Some (Json.Obj (_ :: _)) -> true | _ -> false) in
       let star_res = List.mem "*" resources in
       if allow then begin
         if List.mem "*" actions && star_res then add sid "IAM001" Critical "Allow * on *: this is full administrator access";
         if List.exists (fun a -> let a = String.lowercase_ascii a in a = "*:*" || a = "*") actions && not star_res then add sid "IAM002" High "action wildcard on every service";
         List.iter (fun a -> if String.length a > 2 && String.sub a (String.length a - 2) 2 = ":*" && a <> "*:*" then
                       add sid "IAM002" High (Printf.sprintf "service-wide wildcard %s: grant only the actions needed" a)) actions;
         if Json.member "NotAction" st <> None then add sid "IAM004" High "Allow with NotAction grants everything except the listed actions";
         if Json.member "NotResource" st <> None then add sid "IAM009" Medium "Allow with NotResource applies to everything except the listed resources";
         let hits = List.filter (fun e -> List.exists (fun a -> glob a e) actions) escalation in
         if hits <> [] && not (List.mem "*" actions && star_res) then add sid "IAM006" (if star_res then High else Medium) (Printf.sprintf "privilege escalation path%s: %s" (if star_res then "" else " (scoped resource, still review who can reach it)") (String.concat ", " hits));
         if star_res && not has_cond then begin
           let s = List.filter (fun e -> List.exists (fun a -> glob a e) actions) sensitive_on_star in
           if s <> [] && not (List.mem "*" actions) then add sid "IAM003" High (Printf.sprintf "sensitive actions on Resource *: %s" (String.concat ", " s))
         end;
         (match Json.member "Principal" st with
          | Some (Json.Str "*") when not has_cond -> add sid "IAM005" Critical "Principal * without a Condition: anyone on the internet (fine only for content that is meant to be public)"
          | Some p ->
            (match Json.member "AWS" p with
             | Some v when List.mem "*" (Json.to_strings v) && not has_cond -> add sid "IAM005" Critical "AWS principal * without a Condition: any AWS account"
             | _ -> ())
          | None -> ())
       end)
    (statements doc);
  List.sort (fun a b -> compare (sev_rank a.severity, a.file, a.stmt, a.rule) (sev_rank b.severity, b.file, b.stmt, b.rule)) !out

let esc s =
  let b = Buffer.create (String.length s) in
  String.iter (function '&' -> Buffer.add_string b "&amp;" | '<' -> Buffer.add_string b "&lt;" | '>' -> Buffer.add_string b "&gt;" | '"' -> Buffer.add_string b "&quot;" | c -> Buffer.add_char b c) s;
  Buffer.contents b

let render_text fs =
  let b = Buffer.create 256 in
  Buffer.add_string b (Printf.sprintf "%d findings\n" (List.length fs));
  List.iter (fun f -> Buffer.add_string b (Printf.sprintf "%-9s %s %s [%s]\n          %s\n" (String.uppercase_ascii (sev_name f.severity)) f.rule f.file f.stmt f.message)) fs;
  Buffer.contents b

let render_html fs =
  let rows = Buffer.create 256 in
  List.iter (fun f -> Buffer.add_string rows (Printf.sprintf "<tr><td class=\"%s\">%s</td><td>%s</td><td>%s <span class=\"sub\">[%s]</span></td><td>%s</td></tr>" (sev_name f.severity) (sev_name f.severity) f.rule (esc f.file) (esc f.stmt) (esc f.message))) fs;
  "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>iam-policy-lint</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}.critical{color:#f85149;font-weight:700}.high{color:#f0883e;font-weight:700}.medium{color:#e3b341;font-weight:700}</style></head><body><h1>iam-policy-lint</h1><p class=\"sub\">AWS IAM policy linter in OCaml, standard library only. Synthetic policies, "
  ^ string_of_int (List.length fs) ^ " findings.</p><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>Why it matters</th></tr>" ^ Buffer.contents rows
  ^ "</table><p class=\"sub\">Static analysis of one policy at a time. It does not see permission boundaries, SCPs or what other policies grant the same principal.</p></body></html>\n"
