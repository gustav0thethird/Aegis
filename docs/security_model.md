# Security Model

Aegis implements a robust security model designed to manage access to secrets while ensuring accountability and traceability. This model encompasses API key management and access control mechanisms that facilitate secure interactions between applications and secrets storage.

## API Key Management

Aegis utilizes scoped API keys to authenticate teams. Each team is assigned a unique API key that is tied to a specific team-registry pair. This design ensures that:

- **Isolation of Access**: If Team A and Team B need access to the same registry, they will use different API keys. This isolation means that if one key is compromised, only the affected team’s access needs to be rotated, leaving the other team unaffected.
- **Key Generation and Hashing**: API keys are generated using a secure method and are never stored in plaintext. Instead, Aegis hashes the keys using SHA-256 before storing them, ensuring that even if the database is compromised, the keys remain secure.
- **Key Preview**: Aegis provides a short display form of the keys for use in user interfaces and audit records, which helps maintain usability without compromising security.

The key management functionality is implemented in the `aegis/keys.py` file, which handles the generation, hashing, and formatting of API keys.

## Access Control

Access control in Aegis is enforced through a combination of policies and team configurations:

- **Scoped Access**: Each API key is scoped to a specific team and registry, ensuring that teams can only access the secrets they are authorized to see. This scoped access is a fundamental aspect of Aegis's security model, allowing for fine-grained control over secret retrieval.
- **Policy Enforcement**: Aegis enforces various policies during API requests, including checks for change numbers, IP addresses, and rate limits. These policies are configurable and can be adjusted by administrators through the admin panel.
- **Audit Logging**: Every action taken through the Aegis API is logged with detailed information, including the team identity, registry accessed, objects fetched, source IP, and change number. This immutable logging provides a comprehensive audit trail that can be used for compliance and security reviews.

The access control mechanisms are managed through the `aegis/routers/admin_config.py` file, which allows administrators to define and update settings and policies.

## Conclusion

The security model of Aegis is designed to provide a secure, auditable, and manageable way for teams to access secrets across various vaults. With scoped API keys, stringent access controls, and comprehensive logging, Aegis ensures that sensitive information is protected while allowing teams the flexibility to manage their own access and configurations.
