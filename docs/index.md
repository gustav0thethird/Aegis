# Aegis Overview

Aegis is a vendor-agnostic secrets broker and Privileged Access Management (PAM) gateway designed to enable teams to manage their own secrets securely. It acts as a thin, audited proxy that sits between applications and secrets infrastructure, allowing teams to authenticate using scoped API keys. Each key is tied to a specific team-registry pair, ensuring that teams only access the secrets they are authorized to see, regardless of whether those secrets are stored in CyberArk, HashiCorp Vault, AWS Secrets Manager, or Conjur.

## Key Features

- **Scoped API Keys**: Each team receives a unique API key that is scoped to their specific registry, minimizing the impact of key compromise.
- **Centralized Management**: Admins can manage all secrets through a single panel, allowing for easy migration between vendors without altering application code.
- **Immutable Logging**: Every action, including secret fetches and configuration changes, is logged with detailed attribution, ensuring accountability and traceability.
- **Self-Service Model**: Teams can configure their own webhook subscriptions, notification channels, and CI/CD key rotations without needing to involve the security team.

## Architecture

Aegis is built using FastAPI and Python, designed to scale for organizations with numerous teams and secrets. It supports over 100 teams and 40,000 secrets while allowing a single security team to manage policies rather than operational tasks.

## How It Works

When an application requests a secret, it sends a GET request to Aegis with the API key and change number. Aegis then performs the following steps:

1. **Key Lookup**: Hashes the API key to identify the corresponding team and registry.
2. **Policy Enforcement**: Validates the request against defined policies, including change numbers and rate limits.
3. **Secret Fetching**: Retrieves the requested secrets from the appropriate upstream vault.
4. **Audit Logging**: Records the transaction details in an immutable log.
5. **SIEM Event Emission**: Sends relevant events to a Security Information and Event Management (SIEM) system.

## Conclusion

Aegis provides a robust solution for managing secrets across various platforms, ensuring that teams can operate independently while maintaining security and compliance. Its architecture and features are designed to address the challenges of secrets sprawl and enhance operational efficiency within organizations.
