# Key Management

Aegis manages API keys to ensure secure access to secrets while providing teams with the ability to self-manage their keys. This document outlines the processes for key generation, rotation, and suspension.

## Key Generation

API keys in Aegis are generated using a secure method to ensure uniqueness and randomness. The key generation process is handled by the `generate_key` function in the `aegis/keys.py` file. Each key is prefixed with `sk_` and is generated using the `secrets` library to create a URL-safe token.

### Key Generation Process
1. **Function Call**: When a new key is needed, the `generate_key` function is invoked.
2. **Key Format**: The generated key follows the format `sk_<random_string>`, where `<random_string>` is a securely generated token.
3. **No Plaintext Storage**: Plaintext keys are never stored; instead, they are hashed using SHA-256 before being saved.

## Key Rotation

Key rotation is a critical security practice that Aegis supports. Teams can initiate key rotations through their dashboards or via CI/CD pipelines using auto-generated inbound webhook URLs.

### Key Rotation Process
1. **Initiation**: A team can trigger a rotation either manually through the dashboard or automatically via CI/CD integration.
2. **Key Update**: Upon rotation, a new key is generated, and the previous key is marked as revoked.
3. **Audit Logging**: Each rotation event is logged, capturing details such as the team identity, the registry accessed, and the change number.

## Key Suspension

Aegis allows for the suspension of API keys to prevent unauthorized access without requiring a full key rotation. This feature is particularly useful in cases of suspected compromise.

### Key Suspension Process
1. **Suspension Trigger**: An admin or authorized team member can suspend a key through the admin panel or team dashboard.
2. **Revocation**: The key is marked as suspended in the database, preventing any further access until it is either reactivated or replaced.
3. **Audit Trail**: All suspension actions are logged, ensuring a complete history of key status changes.

## Key Management Overview

- **Scoped Access**: API keys are scoped to specific team-registry pairs, ensuring that if one key is compromised, only the associated team and registry are affected.
- **Self-Service Model**: Teams can manage their own keys, including generating new keys, rotating existing keys, and suspending keys without needing to involve the security team.
- **Immutable Logging**: Every action related to key management is logged with structured before/after diffs, providing full accountability and traceability.

By implementing these key management practices, Aegis ensures that teams can securely manage their access to secrets while maintaining a robust audit trail and minimizing the risk of unauthorized access.
