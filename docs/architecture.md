# Architecture

## Overview

Aegis is designed as a vendor-agnostic secrets broker and PAM (Privileged Access Management) gateway. It acts as an intermediary between applications and various secrets management systems, allowing teams to manage their secrets securely and efficiently. The architecture is built to support scalability and ease of use, enabling teams to self-manage their secret access without needing to involve a central security team for routine operations.

## Components

### Applications

The architecture includes various applications that interact with Aegis:

- **App / Pipeline**: These are the applications or CI/CD pipelines that request secrets from Aegis.
- **CI Runner**: This component triggers key rotations and other automated tasks.
- **Service Mesh**: Facilitates communication between microservices and Aegis.

### Aegis

Aegis itself is built using FastAPI and Python, and consists of several key components:

- **API Gateway**: Handles incoming requests for secrets and other operations.
- **Rate Limiter**: Controls the rate of incoming requests to prevent abuse.
- **Authentication Module**: Validates API keys and manages user sessions.
- **Broker**: Responsible for fetching secrets from various upstream vaults based on the requests it receives.
- **Logging and Auditing**: Maintains an immutable log of all actions taken, including secret fetches, rotations, and configuration changes.

### Upstream Vaults

Aegis interacts with multiple upstream vaults, including:

- **CyberArk**
- **HashiCorp Vault**
- **AWS Secrets Manager**
- **Conjur**

These vaults store the actual secrets that Aegis retrieves based on the requests it receives.

## Interaction Flow

1. **Request Handling**: Applications send requests to Aegis using the `/secrets` endpoint, including an API key and a change number.
2. **Authentication**: Aegis verifies the API key and checks the associated team and registry.
3. **Policy Enforcement**: Aegis enforces access policies based on the request parameters, such as the change number and source IP.
4. **Secret Retrieval**: Aegis fetches the requested secrets from the appropriate upstream vault.
5. **Logging**: Every action taken is logged, including the team identity, registry accessed, and objects fetched.
6. **Response**: Aegis returns the requested secrets to the application.

## Data Model

The data model in Aegis is structured to manage various entities effectively:

- **Objects**: Atomic secret definitions that include vendor, authentication reference, and location.
- **Registries**: Named collections of objects that group related secrets.
- **Teams**: Metadata for teams that access secrets, with many-to-many relationships to registries.
- **Users**: Operator accounts that manage access and permissions.
- **Policies**: Access control rules that govern how teams interact with registries and secrets.

## Conclusion

The architecture of Aegis is designed to provide a robust, scalable, and secure solution for secret management. By acting as a centralized broker, Aegis simplifies the process of accessing secrets across multiple vaults while ensuring that all actions are logged and attributed for accountability. This architecture supports the self-service model, empowering teams to manage their own secret access and notifications without compromising security.
