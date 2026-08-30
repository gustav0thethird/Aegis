# Secret Scanning

## Overview

The secret scanning feature in Aegis is designed to identify and manage sensitive information within your codebase. This functionality is crucial for maintaining security and preventing accidental exposure of credentials.

## Features

- **Normalization of Findings**: Aegis does not execute scanners directly. Instead, it accepts results from various scanning tools that run in Continuous Integration (CI) or pre-commit hooks. The findings from these tools are normalized into a consistent format for easier management and alerting.

- **Supported Scanners**: Aegis can process findings from:
  - **Semgrep**: Use the command `semgrep --json` to generate output.
  - **Gitleaks**: Use the command `gitleaks detect --report-format json` to generate output.
  - **Aegis**: Already normalized findings can be submitted from any other tool.

- **Data Handling**: Matched secrets are not retained. Each finding includes a keyed hash for deduplication and a masked preview for triage purposes. All other details are discarded to ensure sensitive information is not stored.

## Configuration

To configure secret scanning, the following environment variable is utilized:

- **SECRET_KEY**: This key is used to generate the deduplication hash for matched secrets. Rotating this key will make previously identified findings appear as new, which may increase alert noise but does not pose a security risk.

## Severity Levels

Aegis categorizes findings based on severity, which helps prioritize responses:

- **Severities**: The following severity levels are recognized:
  - info
  - low
  - medium
  - high
  - critical

- **Semgrep Severity Mapping**: The severity levels from Semgrep are mapped as follows:
  - ERROR → high
  - WARNING → medium
  - INFO → low

## Masking and Hashing

- **Masking**: Aegis provides a masked preview of secrets to allow for recognition without revealing sensitive information. Short secrets (8 characters or fewer) are fully masked, while longer secrets display a masked format that includes a prefix and the total character count.

- **Hashing**: A keyed hash of matched secrets is generated using HMAC with SHA-256. This approach enhances security by preventing reverse engineering of the hash.

## Fingerprinting

Each finding is assigned a stable identity across scans, which excludes line numbers to avoid re-alerting on the same leaked credential if it moves within the file. This helps maintain the relevance of alerts and reduces alert fatigue.

By implementing these features and configurations, Aegis provides a robust framework for secret scanning, ensuring that sensitive information is effectively managed and protected.
