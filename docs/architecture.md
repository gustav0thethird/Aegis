# Architecture

## Overview

The Aegis system is designed to manage and secure sensitive information, primarily focusing on secret management. It consists of several components that work together to provide a robust and scalable solution.

## Components

### 1. FastAPI Service

The core of Aegis is built using FastAPI, which serves as the web framework for handling HTTP requests. It provides various endpoints for user authentication, secret management, and administrative tasks.

- **Endpoints**:
  - `/health`: Health check endpoint.
  - `/api/login`: User authentication.
  - `/api/my-teams`: Retrieve user teams.
  - `/admin/api`: Administrative functions for managing users, teams, and registries.

### 2. Database Layer

Aegis uses SQLAlchemy as its ORM to interact with a PostgreSQL database. The database schema includes several tables:

- **Objects**: Defines atomic secret definitions.
- **Registries**: Collections of objects.
- **Users**: Operator accounts with roles and team memberships.
- **Policies**: Access control rules.

The database connection is managed through a session factory, ensuring efficient database interactions.

### 3. Secret Management

Aegis integrates with various secret management vendors, including CyberArk, HashiCorp Vault, AWS Secrets Manager, and Conjur. The `broker.py` module is responsible for fetching secrets from these vendors based on the configuration provided in `auth.json`.

### 4. Alerting System

The alerting module (`alerting.py`) is responsible for notifying teams when secrets are found in source code. It supports multiple notification sinks, including Jira, ServiceNow, email, and webhooks. Alerts are configured through environment variables.

### 5. Scanning and Scheduler

Aegis includes a scanning component that identifies secrets in code repositories. The `scheduler.py` module manages the scheduling of these scans and the processing of findings.

### 6. API Key Management

The `keys.py` module handles the generation and hashing of API keys. It ensures that keys are stored securely and are indistinguishable regardless of their source.

### 7. Routers

The application is organized into several routers, each handling specific functionalities:

- **Admin Routers**: Manage users, teams, and logs.
- **Self-Service Routers**: Allow users to manage their own settings and webhooks.
- **Health and Metrics Routers**: Provide health status and metrics for monitoring.

### 8. Configuration Management

Configuration is managed through environment variables and a configuration file (`auth.json`). This allows for flexible deployment in various environments.

### 9. Deployment

Aegis can be deployed using Docker and Docker Compose, with configurations provided for both local and production environments. The deployment process is facilitated by a `Makefile` and CI/CD workflows defined in the `.github` directory.

### 10. Logging and Monitoring

Logging is integrated throughout the application, providing insights into operations and errors. The application can also be configured to send logs to external destinations like S3.

## Conclusion

The architecture of Aegis is modular and designed for extensibility, allowing for easy integration with various secret management solutions and notification systems. Each component is responsible for a specific aspect of the application, ensuring a clear separation of concerns and maintainability.
