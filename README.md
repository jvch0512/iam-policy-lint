# iam-policy-lint

An IAM policy that says `Allow *` on `*` is an incident waiting for a date. Most real risk is subtler: a `PassRole` on every resource, a policy that can rewrite its own permissions, a bucket open to every AWS account. iam-policy-lint reads policy JSON and flags exactly those patterns.

**Live demo:** https://jvch0512.github.io/iam-policy-lint/ (a report on the synthetic policies in `examples/`)

OCaml, standard library only, including its own strict JSON parser.

## Use

```bash
make build
./iam-policy-lint policy.json
./iam-policy-lint ./policies --html > report.html
./iam-policy-lint ./policies --fail-on critical      # exit 1 in CI
```

Point it at a file or a directory of `.json` policies (identity policies, bucket policies, trust policies).

| Rule | Severity | What it catches |
|---|---|---|
| IAM001 | critical | `Allow *` on `*`: full administrator |
| IAM005 | critical | `Principal: *` or `AWS: *` without a Condition |
| IAM002 | high | service-wide wildcards such as `iam:*`, `ec2:*`, or `*:*` |
| IAM003 | high | `iam:PassRole`, `sts:AssumeRole`, `kms:Decrypt`, `secretsmanager:GetSecretValue` and similar on `Resource: *` with no Condition |
| IAM004 | high | `Allow` with `NotAction` |
| IAM006 | high, medium if scoped | privilege escalation paths: `CreatePolicyVersion`, `AttachRolePolicy`, `PutUserPolicy`, `CreateAccessKey`, `UpdateAssumeRolePolicy` and others, including through wildcards |
| IAM008 | medium | missing `Version: 2012-10-17` |
| IAM009 | medium | `Allow` with `NotResource` |

See [examples/policies](examples/policies) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- One policy at a time. It does not see permission boundaries, service control policies or what other policies grant the same principal, so a finding is a place to look, not proof of exposure.
- `Principal: *` is fine for content that is meant to be public (a static assets bucket). The tool cannot know your intent.
- The escalation list covers the well-known IAM paths, not every service-specific one.

## Where it fits

Pre-merge check for Terraform and CloudFormation policy files, cloud security reviews, audit evidence, and a fixed-price "IAM review" for teams that have never had one.

## Tests

```bash
make test    # 36 checks
```

MIT.
