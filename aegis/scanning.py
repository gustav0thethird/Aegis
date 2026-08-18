"""
scanning.py — Normalisation of secret-scanner output.

Aegis does not run scanners. Scanners run where the code is — in CI or at
pre-commit — and POST their results here. This module turns each tool's native
JSON into one shape, so storage, dedupe and alerting do not care which tool
found the secret.

Supported inputs:
  semgrep   — `semgrep --json`
  gitleaks  — `gitleaks detect --report-format json`
  aegis     — already-normalised findings, for any other tool

The matched secret is never retained. A finding carries a keyed hash, used only
to recognise the same secret across scans, and a masked preview for triage.
Everything else is discarded before the finding leaves this module — a broker
that stored the credentials it found in your code would be worse than the
problem it reports.

Config:
  SECRET_KEY — keys the dedupe hash. Rotating it makes previously seen findings
               look new, which is noisy but not harmful.
"""

import hashlib
import hmac
import os

SEVERITIES = ["info", "low", "medium", "high", "critical"]

# Semgrep reports ERROR/WARNING/INFO; a hardcoded credential is worth more than
# the generic mapping suggests, so ERROR is treated as high rather than medium.
_SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class UnsupportedScanner(ValueError):
    """Raised for a scanner name this module cannot normalise."""


def severity_rank(severity: str) -> int:
    """Position in SEVERITIES; unknown values sort lowest."""
    try:
        return SEVERITIES.index((severity or "").lower())
    except ValueError:
        return 0


def meets_threshold(severity: str, threshold: str) -> bool:
    return severity_rank(severity) >= severity_rank(threshold)


def hash_secret(secret: str) -> str:
    """
    Keyed hash of a matched secret, for dedupe only.

    HMAC rather than a bare digest: a plain sha256 of a short or low-entropy
    credential is trivially reversed with a wordlist, and these hashes sit in a
    table that is queried and exported.
    """
    key = os.environ.get("SECRET_KEY", "").encode() or b"aegis-unkeyed"
    return hmac.new(key, (secret or "").encode(), hashlib.sha256).hexdigest()


def mask(secret: str) -> str:
    """
    Masked preview for triage: enough to recognise a credential, not enough to
    use one. Short values are masked completely, since revealing a prefix of an
    8-character secret gives away too much of it.
    """
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * 8}({len(secret)} chars)"


def fingerprint(repository: str, rule_id: str, file_path: str, secret_hash: str) -> str:
    """
    Stable identity for a finding across scans.

    Deliberately excludes line numbers: the same leaked credential moving down a
    file when an import is added is the same finding, and re-alerting on it
    would train people to ignore the alerts.
    """
    parts = "|".join([repository or "", rule_id or "", file_path or "", secret_hash or ""])
    return hashlib.sha256(parts.encode()).hexdigest()


def _finding(repository, rule_id, severity, title, file_path, line_start, line_end,
             secret, description="", validated=False):
    secret_hash = hash_secret(secret)
    return {
        "fingerprint": fingerprint(repository, rule_id, file_path, secret_hash),
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "secret_hash": secret_hash,
        "secret_preview": mask(secret),
        "validated": validated,
    }


def normalize_semgrep(payload: dict, repository: str) -> list[dict]:
    """Normalise `semgrep --json` output."""
    findings = []
    for result in (payload or {}).get("results", []) or []:
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        raw_severity = (metadata.get("severity") or extra.get("severity") or "WARNING")
        severity = _SEMGREP_SEVERITY.get(str(raw_severity).upper(), str(raw_severity).lower())
        if severity not in SEVERITIES:
            severity = "medium"

        findings.append(_finding(
            repository=repository,
            rule_id=result.get("check_id", "semgrep.unknown"),
            severity=severity,
            title=extra.get("message") or result.get("check_id") or "Semgrep finding",
            file_path=result.get("path", ""),
            line_start=(result.get("start") or {}).get("line"),
            line_end=(result.get("end") or {}).get("line"),
            # `lines` is the matched source. It is hashed and masked here and
            # never stored in full.
            secret=extra.get("lines", "") or "",
            description=metadata.get("shortDescription", "") or "",
            validated=bool(extra.get("validation_state") == "CONFIRMED_VALID"),
        ))
    return findings


def normalize_gitleaks(payload, repository: str) -> list[dict]:
    """
    Normalise `gitleaks detect --report-format json` output, which is a bare
    JSON array rather than an object.
    """
    if isinstance(payload, dict):          # some versions wrap it
        payload = payload.get("findings", []) or []
    findings = []
    for item in payload or []:
        # Any credential Gitleaks matches is a real credential by construction,
        # so there is no severity axis to map — these are all high.
        findings.append(_finding(
            repository=repository,
            rule_id=item.get("RuleID") or item.get("ruleID") or "gitleaks.unknown",
            severity="high",
            title=item.get("Description") or "Gitleaks finding",
            file_path=item.get("File") or "",
            line_start=item.get("StartLine"),
            line_end=item.get("EndLine"),
            secret=item.get("Secret") or item.get("Match") or "",
            # Gitleaks' Match field contains the surrounding source line, which
            # includes the credential — deliberately not carried through.
            description="",
            validated=False,
        ))
    return findings


def normalize_aegis(payload: dict, repository: str) -> list[dict]:
    """
    Accept already-normalised findings, so a scanner Aegis does not know about
    can still report through the same pipeline.
    """
    findings = []
    for item in (payload or {}).get("findings", []) or []:
        severity = str(item.get("severity", "medium")).lower()
        if severity not in SEVERITIES:
            severity = "medium"
        findings.append(_finding(
            repository=repository,
            rule_id=item.get("rule_id", "aegis.unknown"),
            severity=severity,
            title=item.get("title") or item.get("rule_id") or "Finding",
            file_path=item.get("file_path", ""),
            line_start=item.get("line_start"),
            line_end=item.get("line_end"),
            secret=item.get("secret", "") or "",
            description=item.get("description", "") or "",
            validated=bool(item.get("validated")),
        ))
    return findings


_NORMALIZERS = {
    "semgrep": normalize_semgrep,
    "gitleaks": normalize_gitleaks,
    "aegis": normalize_aegis,
}

SUPPORTED_SCANNERS = sorted(_NORMALIZERS)


def normalize(scanner: str, payload, repository: str) -> list[dict]:
    """Dispatch to the normaliser for `scanner`, deduplicated by fingerprint."""
    try:
        normalizer = _NORMALIZERS[(scanner or "").lower()]
    except KeyError:
        raise UnsupportedScanner(
            f"Unsupported scanner '{scanner}'. Supported: {', '.join(SUPPORTED_SCANNERS)}"
        )

    seen: dict[str, dict] = {}
    for finding in normalizer(payload, repository):
        # One scan can match the same credential more than once; collapse them
        # so occurrence counts reflect scans, not regex hits.
        seen.setdefault(finding["fingerprint"], finding)
    return list(seen.values())
