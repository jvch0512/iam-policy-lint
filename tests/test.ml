let n = ref 0 and failed = ref 0
let check name c = incr n; if not c then (incr failed; print_endline ("FAIL: " ^ name))

let rules ?(file = "t") text =
  List.map (fun (f : Lint.finding) -> f.rule) (Lint.lint ~file (Json.parse text))

let stmt body = "{\"Version\":\"2012-10-17\",\"Statement\":[" ^ body ^ "]}"
let has r text = List.mem r (rules text)

let () =
  (* json parser *)
  check "json: object and array" (Json.parse "{\"a\":[1,2,{\"b\":null}]}" = Json.Obj [ ("a", Json.Arr [ Json.Num 1.; Json.Num 2.; Json.Obj [ ("b", Json.Null) ] ]) ]);
  check "json: escapes" (Json.parse "\"a\\n\\u0041\"" = Json.Str "a\nA");
  List.iter (fun bad -> check ("json rejects " ^ bad) (try ignore (Json.parse bad); false with Json.Parse_error _ -> true)) [ "{"; "[1,]"; "{\"a\" 1}"; "tru"; "\"x"; "1 2"; "" ];
  check "json: deep nesting is refused, not a crash" (try ignore (Json.parse (String.make 500 '[')); false with Json.Parse_error _ -> true);
  (* glob *)
  check "glob: service wildcard" (Lint.glob "iam:*" "iam:CreateAccessKey");
  check "glob: case-insensitive" (Lint.glob "IAM:createaccesskey" "iam:CreateAccessKey");
  check "glob: no match" (not (Lint.glob "s3:*" "iam:PassRole"));
  check "glob: middle wildcard" (Lint.glob "iam:Attach*Policy" "iam:AttachRolePolicy");
  (* rules *)
  check "IAM001 admin" (has "IAM001" (stmt "{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}"));
  check "admin is not also reported as escalation" (not (has "IAM006" (stmt "{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}")));
  check "Deny is never a finding" (rules (stmt "{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}") = []);
  check "IAM002 service wildcard" (has "IAM002" (stmt "{\"Effect\":\"Allow\",\"Action\":\"ec2:*\",\"Resource\":\"arn:aws:ec2:*\"}"));
  check "IAM003 passrole on star" (has "IAM003" (stmt "{\"Effect\":\"Allow\",\"Action\":\"iam:PassRole\",\"Resource\":\"*\"}"));
  check "IAM003 not when scoped" (not (has "IAM003" (stmt "{\"Effect\":\"Allow\",\"Action\":\"iam:PassRole\",\"Resource\":\"arn:aws:iam::1:role/x\"}")));
  check "IAM003 not when a condition exists" (not (has "IAM003" (stmt "{\"Effect\":\"Allow\",\"Action\":\"iam:PassRole\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"lambda.amazonaws.com\"}}}")));
  check "IAM004 NotAction" (has "IAM004" (stmt "{\"Effect\":\"Allow\",\"NotAction\":\"iam:*\",\"Resource\":\"*\"}"));
  check "IAM005 public principal" (has "IAM005" (stmt "{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::b/*\"}"));
  check "IAM005 not with a condition" (not (has "IAM005" (stmt "{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::b/*\",\"Condition\":{\"StringEquals\":{\"aws:SourceVpce\":\"vpce-1\"}}}")));
  check "IAM005 AWS star" (has "IAM005" (stmt "{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"sts:AssumeRole\"}"));
  check "IAM006 escalation by wildcard" (has "IAM006" (stmt "{\"Effect\":\"Allow\",\"Action\":\"iam:*\",\"Resource\":\"*\"}"));
  check "IAM006 scoped is medium" (List.exists (fun (f : Lint.finding) -> f.rule = "IAM006" && f.severity = Lint.Medium) (Lint.lint ~file:"t" (Json.parse (stmt "{\"Effect\":\"Allow\",\"Action\":\"iam:PutRolePolicy\",\"Resource\":\"arn:aws:iam::1:role/x\"}"))));
  check "IAM008 missing version" (has "IAM008" "{\"Statement\":[]}");
  check "IAM009 NotResource" (has "IAM009" (stmt "{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"NotResource\":\"arn:aws:s3:::secret/*\"}"));
  check "single statement object is accepted" (has "IAM001" "{\"Version\":\"2012-10-17\",\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}");
  check "a least-privilege policy is clean" (rules (stmt "{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::reports/*\"}") = []);
  (* html *)
  let evil = [ { Lint.file = "<b>"; stmt = "<i>"; rule = "IAM001"; severity = Lint.High; message = "<script>alert(1)</script>" } ] in
  let h = Lint.render_html evil in
  let contains s sub = let ls = String.length s and lb = String.length sub in let rec go i = i + lb <= ls && (String.sub s i lb = sub || go (i + 1)) in go 0 in
  check "html escapes input" (not (contains h "<script>alert") && contains h "&lt;script&gt;");
  check "html has strict CSP" (contains h "default-src 'none'");
  (* samples *)
  (try
     let read p = let ic = open_in_bin p in let s = really_input_string ic (in_channel_length ic) in close_in ic; s in
     let fs = List.concat_map (fun f -> Lint.lint ~file:f (Json.parse (read ("examples/policies/" ^ f)))) [ "admin-everything.json"; "ci-deployer.json"; "everything-but.json"; "public-bucket.json"; "read-only-analyst.json" ] in
     check "sample: 9 findings" (List.length fs = 9);
     check "sample: the clean policy has none" (not (List.exists (fun (f : Lint.finding) -> f.file = "read-only-analyst.json") fs));
     check "sample: three critical" (List.length (List.filter (fun (f : Lint.finding) -> f.severity = Lint.Critical) fs) = 3)
   with Sys_error _ -> print_endline "skipped sample tests (run from repo root)");
  print_endline (if !failed = 0 then Printf.sprintf "all %d passed" !n else Printf.sprintf "%d of %d failed" !failed !n);
  exit (if !failed = 0 then 0 else 1)
