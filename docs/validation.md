# Validation on real data

Counts below were produced by running the tool on public data, not on the synthetic samples in `examples/`.

## Corpus
SummitRoute/aws_managed_policies at commit `c50715d`: 628 AWS managed policies, renamed to `.json`.

## Result
394 findings: 302 IAM002 (service-wide wildcard), 75 IAM003, 13 IAM006, 2 IAM009, 1 IAM004 and 1 critical IAM001.

## What the real data exposed (all fixed, with regression tests)
- Policies wrapped by the AWS CLI (`get-policy-version`, `get-role-policy`, `get-account-authorization-details`) or several policies in one file were not analysed. `lint_file` now finds every object that holds a `Statement`.

## Limits
AWS managed policies are broad by design (many are `*FullAccess`). The counts show what the linter sees, not that AWS policies are defective.
