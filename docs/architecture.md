# Architecture

## Overview

The Aegis system is designed to manage and secure secrets across various platforms. It consists of several components that work together to provide a cohesive solution for secret management.

## Components

### FastAPI Application

The core of Aegis is built using FastAPI, which serves as the web framework for handling HTTP requests. The application exposes various endpoints for user authentication, secret management, and administrative functions.

### Database

Aegis utilizes SQLAlchemy for database interactions. The database schema includes tables for objects, registries, teams, users, and logs, among others. The connection to the database is managed through a session factory, allowing for efficient database operations.

### Secret Management

Aegis integrates with multiple secret management vendors, including CyberArk, HashiCorp Vault, AWS Secrets Manager, and Conjur. The `broker.py` module is responsible for fetching secrets from these vendors based on the configuration defined in `auth.json`.

### Alerting System

The alerting module (`alerting.py`) is responsible for notifying teams when secrets are detected in source code. It supports multiple notification sinks, including Jira, ServiceNow, email, and webhooks. Alerts are raised based on the severity of findings and are configurable through environment variables.

### API Endpoints

The API is structured into several routers, each handling specific functionalities:

- **Admin Routers**: Manage users, teams, registries, and settings.
- **User Routers**: Allow users to manage their webhooks and view metrics.
- **Health Check**: Provides a simple endpoint to check the health of the application.
- **Metrics**: Exposes team-scoped metrics for monitoring.

### Scheduler

The scheduler component is responsible for periodic tasks, such as scanning for secrets and managing key rotations. It ensures that the system remains up-to-date with the latest security practices.

### Webhooks

Aegis supports webhooks for real-time notifications. The webhook configuration is managed per team, allowing for customized integration with external systems.

### Logging and Auditing

The system maintains logs for all operations, including changes made by administrators and audit logs for user actions. This ensures traceability and accountability within the application.

### Configuration Management

Configuration is managed through environment variables and a configuration file. This allows for flexible deployment across different environments, such as local development and production.

### Deployment

Aegis can be deployed using Docker, with configurations provided for both local and cloud environments. The deployment process is facilitated through Docker Compose and Helm charts for Kubernetes.

### Security Considerations

Aegis emphasizes security by ensuring that sensitive information, such as API keys and secrets, is never stored in plaintext. All secrets are fetched dynamically from the configured secret management systems.

## Conclusion

The architecture of Aegis is modular and designed for scalability and security. Each component plays a critical role in ensuring that secrets are managed effectively while providing a user-friendly interface for interaction.
