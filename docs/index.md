# Overview

Aegis is a vendor-agnostic secrets broker and Privileged Access Management (PAM) gateway designed to enable teams to manage their own API keys and secrets securely. It acts as a thin, audited proxy that sits between applications and various secrets infrastructures, allowing for centralized management of secrets across multiple vaults such as CyberArk, HashiCorp Vault, AWS Secrets Manager, and Conjur.

## Key Features

- **Scoped API Keys**: Each team is assigned a unique API key that is scoped to a specific team-registry pair, ensuring that teams only access the secrets they are authorized to see.
- **Centralized Management**: Aegis provides a single endpoint for applications to retrieve secrets, simplifying the management of secrets across different systems.
- **Immutable Logging**: Every action, including secret fetches, rotations, and configuration changes, is logged with structured before/after diffs and full account attribution, ensuring traceability.
- **Self-Service Model**: Teams can manage their own webhook subscriptions, notification channels, and CI/CD key rotations through a dedicated dashboard, reducing reliance on security teams for operational tasks.
- **Scalability**: Aegis is designed to support large organizations with 100+ teams and 40,000+ secrets, allowing a single security team to manage policies without being overwhelmed by operational tasks.

## Architecture

Aegis operates as a FastAPI application that interacts with upstream vaults to fetch secrets based on authenticated requests. The architecture includes components for rate limiting, authentication, and logging, ensuring secure and efficient operations.

## How It Works

When an application requests a secret, it sends a GET request to Aegis with its API key and change number. Aegis then performs the following steps:

1. **Key Lookup**: It hashes the API key to identify the corresponding team and registry.
2. **Policy Enforcement**: Aegis checks the request against defined policies, including change numbers and rate limits.
3. **Secret Retrieval**: It fetches the required secrets from the appropriate upstream vault.
4. **Audit Logging**: The request details are logged for accountability.
5. **SIEM Event Emission**: An event is emitted for security information and event management (SIEM) systems.

## Conclusion

Aegis provides a robust solution for managing secrets across various platforms, enabling teams to operate independently while maintaining security and compliance. Its focus on self-service, logging, and scalability makes it a valuable tool for organizations looking to streamline their secrets management processes.
