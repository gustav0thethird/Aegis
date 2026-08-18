"""
Unit tests for secret-scanner output normalisation.

No database or network. The property these tests exist to protect is that the
matched credential never survives normalisation — a broker that stored the
secrets it found in your code would be worse than the problem it reports.
"""

import pytest

from aegis import scanning

SECRET = "AKIAIOSFODNN7EXAMPLE"
REPO = "acme/payments"

SEMGREP = {
    "results": [
        {
            "check_id": "generic.secrets.aws-access-key",
            "path": "src/config.py",
            "start": {"line": 12},
            "end": {"line": 12},
            "extra": {
                "message": "AWS access key detected",
                "severity": "ERROR",
                "lines": SECRET,
                "metadata": {"shortDescription": "Hardcoded AWS credential"},
            },
        }
    ]
}

GITLEAKS = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "src/config.py",
        "StartLine": 12,
        "EndLine": 12,
        "Secret": SECRET,
        "Match": f"aws_key = {SECRET}",
    }
]


def _flatten(findings):
    """Every string a finding carries, for leak checking."""
    out = []
    for f in findings:
        out.extend(str(v) for v in f.values())
    return " ".join(out)


class TestSecretsAreNotRetained:

    @pytest.mark.parametrize("scanner,payload", [("semgrep", SEMGREP), ("gitleaks", GITLEAKS)])
    def test_raw_secret_never_appears_in_a_finding(self, scanner, payload):
        findings = scanning.normalize(scanner, payload, REPO)
        assert findings
        assert SECRET not in _flatten(findings)

    def test_gitleaks_match_line_is_not_carried_through(self):
        """Match contains the surrounding source, including the credential."""
        findings = scanning.normalize("gitleaks", GITLEAKS, REPO)
        assert "aws_key =" not in _flatten(findings)

    def test_preview_is_masked(self):
        findings = scanning.normalize("gitleaks", GITLEAKS, REPO)
        preview = findings[0]["secret_preview"]
        assert preview.startswith("AKIA")
        assert "*" in preview
        assert SECRET not in preview


class TestMask:

    def test_short_secrets_are_fully_masked(self):
        assert scanning.mask("abcd1234") == "*" * 8

    def test_long_secrets_keep_only_a_short_prefix(self):
        masked = scanning.mask(SECRET)
        assert masked.startswith("AKIA")
        assert str(len(SECRET)) in masked

    def test_empty_is_empty(self):
        assert scanning.mask("") == ""


class TestHashSecret:

    def test_is_stable(self):
        assert scanning.hash_secret(SECRET) == scanning.hash_secret(SECRET)

    def test_differs_per_secret(self):
        assert scanning.hash_secret(SECRET) != scanning.hash_secret("other")

    def test_is_keyed_by_secret_key(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "key-one")
        first = scanning.hash_secret(SECRET)
        monkeypatch.setenv("SECRET_KEY", "key-two")
        assert scanning.hash_secret(SECRET) != first


class TestFingerprint:

    def test_same_leak_same_fingerprint(self):
        a = scanning.normalize("gitleaks", GITLEAKS, REPO)[0]
        b = scanning.normalize("gitleaks", GITLEAKS, REPO)[0]
        assert a["fingerprint"] == b["fingerprint"]

    def test_line_movement_does_not_change_identity(self):
        """A credential shifting down a file is the same finding, not a new one."""
        moved = [dict(GITLEAKS[0], StartLine=98, EndLine=98)]
        assert (scanning.normalize("gitleaks", GITLEAKS, REPO)[0]["fingerprint"]
                == scanning.normalize("gitleaks", moved, REPO)[0]["fingerprint"])

    def test_different_repository_is_a_different_finding(self):
        assert (scanning.normalize("gitleaks", GITLEAKS, REPO)[0]["fingerprint"]
                != scanning.normalize("gitleaks", GITLEAKS, "acme/other")[0]["fingerprint"])

    def test_different_file_is_a_different_finding(self):
        elsewhere = [dict(GITLEAKS[0], File="src/other.py")]
        assert (scanning.normalize("gitleaks", GITLEAKS, REPO)[0]["fingerprint"]
                != scanning.normalize("gitleaks", elsewhere, REPO)[0]["fingerprint"])


class TestSemgrep:

    def test_maps_fields(self):
        f = scanning.normalize("semgrep", SEMGREP, REPO)[0]
        assert f["rule_id"] == "generic.secrets.aws-access-key"
        assert f["file_path"] == "src/config.py"
        assert f["line_start"] == 12
        assert f["title"] == "AWS access key detected"

    def test_error_maps_to_high(self):
        assert scanning.normalize("semgrep", SEMGREP, REPO)[0]["severity"] == "high"

    def test_warning_maps_to_medium(self):
        payload = {"results": [dict(SEMGREP["results"][0])]}
        payload["results"][0]["extra"] = dict(SEMGREP["results"][0]["extra"],
                                              severity="WARNING", metadata={})
        assert scanning.normalize("semgrep", payload, REPO)[0]["severity"] == "medium"

    def test_unknown_severity_falls_back_to_medium(self):
        payload = {"results": [dict(SEMGREP["results"][0])]}
        payload["results"][0]["extra"] = dict(SEMGREP["results"][0]["extra"],
                                              severity="WEIRD", metadata={})
        assert scanning.normalize("semgrep", payload, REPO)[0]["severity"] == "medium"

    def test_empty_results(self):
        assert scanning.normalize("semgrep", {"results": []}, REPO) == []

    def test_missing_results_key(self):
        assert scanning.normalize("semgrep", {}, REPO) == []


class TestGitleaks:

    def test_maps_fields(self):
        f = scanning.normalize("gitleaks", GITLEAKS, REPO)[0]
        assert f["rule_id"] == "aws-access-token"
        assert f["title"] == "AWS Access Token"
        assert f["file_path"] == "src/config.py"

    def test_detected_credentials_are_high(self):
        assert scanning.normalize("gitleaks", GITLEAKS, REPO)[0]["severity"] == "high"

    def test_empty_report(self):
        assert scanning.normalize("gitleaks", [], REPO) == []

    def test_wrapped_object_form(self):
        assert len(scanning.normalize("gitleaks", {"findings": GITLEAKS}, REPO)) == 1


class TestDispatchAndDedupe:

    def test_duplicate_matches_in_one_scan_collapse(self):
        payload = GITLEAKS + GITLEAKS
        assert len(scanning.normalize("gitleaks", payload, REPO)) == 1

    def test_unsupported_scanner_raises(self):
        with pytest.raises(scanning.UnsupportedScanner, match="trufflehog"):
            scanning.normalize("trufflehog", {}, REPO)

    def test_error_names_the_supported_scanners(self):
        with pytest.raises(scanning.UnsupportedScanner, match="semgrep"):
            scanning.normalize("nope", {}, REPO)

    def test_generic_format_is_accepted(self):
        payload = {"findings": [{
            "rule_id": "custom.rule", "severity": "critical", "title": "Custom",
            "file_path": "a.py", "line_start": 1, "secret": SECRET,
        }]}
        f = scanning.normalize("aegis", payload, REPO)[0]
        assert f["severity"] == "critical"
        assert SECRET not in _flatten([f])


class TestSeverityThreshold:

    @pytest.mark.parametrize("severity,threshold,expected", [
        ("critical", "high", True),
        ("high", "high", True),
        ("medium", "high", False),
        ("low", "info", True),
        ("info", "critical", False),
    ])
    def test_meets_threshold(self, severity, threshold, expected):
        assert scanning.meets_threshold(severity, threshold) is expected

    def test_unknown_severity_sorts_lowest(self):
        assert scanning.meets_threshold("banana", "low") is False
