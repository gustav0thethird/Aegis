# Usage

Aegis serves as a vendor-agnostic secrets broker and PAM gateway, allowing teams to manage their secrets securely and efficiently. This document provides instructions on how to use Aegis, including API calls and integration with CI/CD pipelines.

## API Calls

### Authentication

To interact with Aegis, you must authenticate using a scoped API key. Each team is assigned a unique API key that corresponds to a specific team-registry pair.

#### Example Request

```http
GET /secrets
X-API-Key: sk_...
X-Change-Number: CHG123
```

### Secrets Endpoint

The primary endpoint for fetching secrets is `/secrets`. When a request is made, Aegis performs the following actions:

1. Hashes the API key to look up the associated team and registry.
2. Enforces policies based on the provided change number, IP address, and rate limits.
3. Fetches the secrets from the appropriate upstream vault (e.g., CyberArk, HashiCorp Vault, AWS Secrets Manager).
4. Writes an audit log detailing the request.
5. Emits a SIEM event for monitoring.

### User Self-Service API

Teams can manage their own webhook subscriptions, notification channels, and CI/CD key rotations through the User Self-Service API. This allows for greater autonomy without needing to involve the security team.

## CI/CD Integration

Aegis can be integrated into CI/CD pipelines to automate key rotations and secret scanning. Below is an example of how to set up a GitHub Actions workflow for secret scanning.

### GitHub Actions Workflow

To implement secret scanning in your repository, create a file named `.github/workflows/secret-scan.yml` and include the following configuration:

```yaml
name: Secret scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 3 * * 1"

jobs:
  secret-scan:
    uses: gustav0thethird/Aegis/.github/workflows/secret-scan.yml@main
    with:
      aegis-url: https://aegis.example.com
      team-id: 00000000-0000-0000-0000-000000000000
      fail-on-findings: true
    secrets:
      aegis-token: ${{ secrets.AEGIS_TOKEN }}
```

### Setup Instructions

1. **Enable Inbound Webhook**: In Aegis, enable the team's inbound webhook and copy its signing secret.
2. **Add Repository Secret**: Add the signing secret as a repository secret named `AEGIS_TOKEN`.
3. **Replace Team ID**: Update the `team-id` field with your team's UUID.

By following these steps, your CI/CD pipeline will automatically trigger secret scans on code pushes and pull requests, ensuring that sensitive information is not inadvertently committed.

## Conclusion

Aegis provides a robust framework for managing secrets across multiple vendors while allowing teams to operate independently. By utilizing the API and integrating with CI/CD pipelines, organizations can enhance their security posture and streamline operations.
