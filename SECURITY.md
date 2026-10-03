# Security policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/wif1c0ldspot/ragguard/security/advisories/new)
for exploitable scanner bypasses, accidental release of withheld content,
authorization-related integration flaws, sensitive-data exposure or dependency
vulnerabilities. Avoid public issues and pull requests containing undisclosed
exploits, real credentials or private source material.

Include the affected commit or package version, Python/Node versions, policy and
integration configuration, a minimal synthetic reproduction, expected versus
actual behavior, and the trust boundary affected. Distinguish content that was
merely flagged incorrectly from content that an enforcing integration released.
If possible, describe a mitigation without attaching real production data.

If the private reporting form is unavailable, do not paste vulnerability details
into a public issue. A public request to enable private reporting may identify the
need for a reporting channel without disclosing the issue itself.

## Maintenance scope

This is an alpha project. There is no LTS or backport commitment and no guaranteed
response time. Reports against the current default branch and latest repository
release are most useful; include older affected versions when known. Repository
tags and CI artifacts do not by themselves establish a PyPI or npm release.

Ragguard uses heuristic rules and cannot guarantee detection of every injection.
An accepted result is not proof that content is safe. Read the
[threat model](docs/THREAT_MODEL.md) and enforce authorization, least privilege,
side-effect controls and review policy in the host application. Please report
unexpected fail-open behavior even when a rule itself is operating as designed.

## Handling reports and evidence

Finding evidence and reports can contain private material despite targeted
redaction. Keep them access-controlled, minimize retention, and share synthetic
reproductions where possible. Never publish raw reports merely because known
credential formats have been redacted.
