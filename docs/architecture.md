# Architecture

Aegis is designed as a vendor-agnostic secrets broker and PAM (Privileged Access Management) gateway, facilitating secure access to secrets stored across various vaults. The architecture comprises several key components that interact to manage secrets effectively.

## Components

### Applications
- **Applications**: These include any client applications or CI/CD pipelines that interact with Aegis to retrieve secrets.
- **Service Mesh**: Facilitates communication between microservices and Aegis.

### Aegis Core
- **FastAPI Service**: The core of Aegis is built using FastAPI, which handles incoming requests and routes them to appropriate handlers.
- **API Endpoints**:
  - `GET /secrets`: Main endpoint for fetching secrets, requiring an API key and change number.
  - Authentication endpoints for user sessions and self-service functionalities.
  
### Rate Limiter
- **Rate Limiter**: Ensures that requests to the Aegis service are controlled to prevent abuse and manage load effectively.

### Authentication
- **Key Authentication**: Each request to Aegis must include a scoped API key that identifies the team and registry, ensuring that only authorized requests are processed.

### Broker
- **Secrets Broker**: The `broker.py` component fetches secrets from various upstream vaults by grouping objects by vendor and acquiring necessary authentication sessions. It supports multiple vaults, including CyberArk, HashiCorp Vault, AWS Secrets Manager, and Conjur.

### Database
- **Database Layer**: Utilizes SQLAlchemy for ORM, managing the storage of secrets, registries, teams, and access control policies. The database schema includes:
  - **Objects**: Definitions of secrets, including vendor and location.
  - **Registries**: Collections of objects.
  - **Teams**: Metadata for team management.
  - **Policies**: Access control rules governing secret retrieval.

### Logging and Auditing
- **Audit Logging**: Every action taken through Aegis is logged, capturing details such as team identity, registry accessed, and the specific secrets fetched. This immutable log supports compliance and security auditing.

### Webhooks and Notifications
- **Webhook Configuration**: Teams can configure their own webhooks for notifications and CI/CD integrations, allowing for automated key rotations and alerts without needing security team intervention.

### Metrics and Monitoring
- **Metrics Collection**: Aegis provides team-scoped metrics for monitoring usage and performance, which can be integrated with systems like Prometheus for visualization.

## Interaction Flow

1. **Request Handling**: Applications send requests to Aegis using the `GET /secrets` endpoint, including the necessary API key and change number.
2. **Authentication**: Aegis verifies the API key and enforces policies based on the request context (e.g., IP address, time window).
3. **Secrets Retrieval**: The broker fetches the requested secrets from the appropriate vault based on the registry configuration.
4. **Logging**: Aegis logs the request details, including team identity and fetched secrets, to maintain an immutable audit trail.
5. **Response**: The secrets are returned to the requesting application in a structured format.

## Conclusion

The architecture of Aegis is built to provide a robust, scalable solution for managing secrets across various vaults while ensuring security and compliance through detailed logging and auditing. Each component plays a critical role in facilitating seamless interactions between applications and the underlying secrets infrastructure.
