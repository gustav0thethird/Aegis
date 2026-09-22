# Architecture

Aegis is designed as a vendor-agnostic secrets broker and PAM gateway, facilitating the management of secrets across various vaults. The architecture consists of several key components that interact to provide a secure and efficient means of accessing secrets.

## Components

### 1. **Applications**
Applications interact with Aegis through a unified API. They send requests to fetch secrets using scoped API keys, which are tied to specific teams and registries.

### 2. **Aegis Core**
The core of Aegis is built around a FastAPI service that handles incoming requests, manages authentication, and routes operations to the appropriate components.

#### Key Files:
- **`aegis/api.py`**: Implements the FastAPI service, providing endpoints for user authentication, team management, and administrative functions.
- **`aegis/broker.py`**: Responsible for fetching secrets from various vaults. It groups requests by vendor and manages authentication sessions.
- **`aegis/database.py`**: Sets up the SQLAlchemy engine and session factory for database interactions, ensuring efficient data handling.
- **`aegis/models.py`**: Defines the SQLAlchemy ORM models that represent the data structure for secrets, registries, teams, and access control.

### 3. **Secrets Management**
Aegis acts as a proxy between applications and multiple secrets vaults, including CyberArk, HashiCorp Vault, AWS Secrets Manager, and Conjur. It abstracts the complexity of interacting with different vaults, allowing teams to focus on their specific needs.

### 4. **Authentication and Authorization**
Aegis employs a scoped API key system, where each team is assigned a unique key for accessing specific registries. This ensures that secrets are only accessible to authorized teams, and every action is logged for accountability.

### 5. **Logging and Auditing**
Every interaction with Aegis is logged, capturing details such as team identity, registry accessed, objects fetched, source IP, and change numbers. This immutable logging provides a comprehensive audit trail for compliance and security purposes.

### 6. **Self-Service Model**
Teams can manage their own webhook subscriptions, notification channels, and CI/CD key rotations through a dedicated dashboard. This reduces the operational burden on security teams and allows for quicker response times to changes.

### 7. **Database Schema**
The database schema is designed to support the various entities involved in secrets management:
- **Objects**: Atomic secret definitions, including vendor, authentication reference, and location.
- **Registries**: Named collections of objects.
- **Teams**: Metadata for team management, including access control policies.
- **Webhooks**: Configuration for outgoing notifications and event subscriptions.
- **Logs**: Immutable records of requests and administrative changes.

### 8. **Request Lifecycle**
The request lifecycle in Aegis follows a structured flow:
1. Applications send a request to Aegis with the API key and change number.
2. Aegis verifies the key, looks up the associated team and registry, and enforces policies.
3. Secrets are fetched from the appropriate vault based on the vendor.
4. An audit log entry is created for the request.
5. A SIEM event may be emitted for monitoring purposes.

### 9. **CI/CD Integration**
Aegis supports CI/CD pipelines through inbound webhooks, allowing automated key rotations without manual intervention.

## Conclusion
The architecture of Aegis is designed to provide a scalable, secure, and efficient means of managing secrets across various vaults. By abstracting the complexities of different secrets management solutions, Aegis enables teams to focus on their core responsibilities while maintaining strict security and compliance standards.
