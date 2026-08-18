# CI integration examples

Aegis does not run secret scanners. Scanners run where the code is — in the
pipeline and at pre-commit — and report their findings back, so the broker
never needs credentials for your repositories or a place to clone them.

| File | Purpose |
|---|---|
| `github-actions-secret-scan.yml` | Drop-in caller for the reusable workflow Aegis publishes |
| `pre-commit-config.yaml` | Local gate that blocks the commit before the secret ever lands |
| `gitleaks.toml` | Allowlist template for test fixtures and documented example values |

## How reporting works

Each scanner's native JSON is POSTed to
`POST {AEGIS_URL}/api/scan/{team_id}/ingest`, authenticated with the team's
inbound webhook secret. Aegis normalises Semgrep and Gitleaks output into one
shape, deduplicates by fingerprint so a leak that stays in the codebase raises
one ticket rather than one per pipeline run, and alerts through whichever sinks
the deployment has configured.

The matched credential is never sent in full: findings carry a keyed hash for
deduplication and a masked preview for triage.

## Two things worth deciding deliberately

**Whether a finding fails the build.** `fail-on-findings: true` stops the
pipeline when something new is detected. That is the right default for most
teams, but it does mean a false positive blocks a merge — which is why the
allowlist template exists.

**Reporting failures are warnings, not build failures.** If Aegis is
unreachable, the workflow warns and carries on. A findings count of zero has to
mean "nothing was found", never "the broker was down", so the local scan result
still gates the build on its own.
