# Security Policy

Aegis is a secrets broker. A vulnerability in it is a vulnerability in every
secret it fronts, so reports are taken seriously and handled privately.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting:

https://github.com/gustav0thethird/Aegis/security/advisories/new

Include what you can of:

- Affected version or commit
- Vendor backend involved, if any (CyberArk, Vault, AWS, Conjur)
- Steps to reproduce, or a proof of concept
- Impact as you understand it

You will get an acknowledgement within 72 hours. Once a fix is available a
GitHub Security Advisory will be published crediting the reporter, unless you
ask not to be named.

## Supported versions

Aegis is pre-1.0. Only the latest release and `main` receive security fixes.

## Scope

In scope:

- Anything reachable through the Aegis API, admin panel, or team dashboard
- Authentication, key scoping, policy enforcement, and audit logging
- Vendor adapter behaviour that could leak or mis-scope secrets

Out of scope:

- Vulnerabilities in the upstream vault products themselves — report those to
  the vendor
- Findings that require an already-compromised admin account or host
- Automated scanner output with no demonstrated impact

## What's already in place

- Secret scanning with push protection on this repository
- CodeQL and Bandit static analysis on every push and pull request
- Dependabot security updates
- Gitleaks in CI (`.gitleaks.toml`)
- Trivy, Semgrep, Hadolint and tflint on every push and pull request
- Every action in CI pinned to a commit SHA
- Release images carry an SPDX SBOM and SLSA provenance, and are signed
  with Sigstore (keyless). Verify a tag with:

  ```
  cosign verify ghcr.io/gustav0thethird/aegis:<tag>     --certificate-identity-regexp 'https://github.com/gustav0thethird/Aegis/'     --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
