# Secret Scanning

Aegis provides capabilities for secret scanning by normalizing the output from various secret scanning tools. The scanning process does not occur within Aegis itself; instead, it relies on external scanners that run in Continuous Integration (CI) environments or during pre-commit hooks. These scanners post their results to Aegis, which then processes and stores the findings.

## Supported Scanners

Aegis currently supports the following scanners:

- **Semgrep**: Use the command `semgrep --json` to generate output.
- **Gitleaks**: Use the command `gitleaks detect --report-format json` to generate output.
- **Aegis**: Accepts already-normalized findings from any other tool.

## Data Handling

When a secret is detected, Aegis does not retain the matched secret itself. Instead, each finding includes:

- A keyed hash used for deduplication, ensuring that the same secret across different scans is recognized without storing the actual secret.
- A masked preview of the secret for triage purposes.

All other information is discarded before the finding is processed further. This design choice ensures that sensitive information is not stored, mitigating the risk of exposing credentials.

## Configuration

Aegis requires the following configuration for its secret scanning capabilities:

- **SECRET_KEY**: This environment variable is used to generate the deduplication hash. Rotating this key will make previously seen findings appear new, which may increase alert noise but does not pose a security risk.

## Severity Levels

Findings are categorized into severity levels, which are ranked as follows:

- **info**
- **low**
- **medium**
- **high**
- **critical**

The severity levels are determined based on the output from the scanners. For example, Semgrep's severity levels are mapped as follows:

- `ERROR` is treated as **high**
- `WARNING` is treated as **medium**
- `INFO` is treated as **low**

## Functions

Aegis includes several functions to handle secret scanning:

- **hash_secret(secret: str) -> str**: Generates a keyed hash of a matched secret for deduplication.
- **mask(secret: str) -> str**: Provides a masked preview of the secret for recognition without revealing sensitive information.
- **fingerprint(repository: str, rule_id: str, file_path: str, secret_hash: str) -> str**: Creates a stable identity for a finding across scans, deliberately excluding line numbers to avoid re-alerting on the same secret.

## Conclusion

Aegis's secret scanning capabilities are designed to efficiently process and manage findings from various scanning tools while ensuring that sensitive information is not stored. Proper configuration and understanding of severity levels are essential for effective use of the secret scanning feature.
