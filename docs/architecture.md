# Architecture

The architecture of Aegis is designed to facilitate the management of secrets across various vaults while ensuring security, scalability, and ease of use. Below are the key components and their interactions.

## Overview

Aegis acts as a vendor-agnostic secrets broker and PAM (Privileged Access Management) gateway. It provides a unified API for applications to access secrets stored in different vaults, such as CyberArk, HashiCorp Vault, AWS Secrets Manager, and Conjur. The architecture is built to support multiple teams, allowing them to self-manage their secrets while maintaining strict access controls and logging.

## Components

### 1. **Broker**

The broker is responsible for fetching secrets from various vaults. It groups objects by vendor and acquires authentication sessions as needed. The main entry point is the `fetch_secrets` function, which takes in object rows and an authentication dictionary, returning the requested secrets.

- **File**: `aegis/broker.py`
- **Key Function**: `fetch_secrets(object_rows, auth)`

### 2. **Database**

Aegis uses SQLAlchemy for database interactions. The database schema includes tables for managing secrets, registries, teams, and access control. The `SessionLocal` object is used to manage database sessions.

- **File**: `aegis/database.py`
- **Key Classes**: `Base`, `get_db()`

### 3. **Models**

The models define the structure of the database tables, including objects, registries, teams, policies, and logs. Each model corresponds to a specific table in the database, facilitating the organization and retrieval of secrets and related metadata.

- **File**: `aegis/models.py`
- **Key Models**: `Object`, `Registry`, `Team`, `Policy`, `AuditLog`

### 4. **API**

The FastAPI service provides endpoints for user authentication, secret management, and administrative functions. It handles incoming requests and routes them to the appropriate functions, ensuring that all actions are logged and attributed.

- **File**: `aegis/api.py`
- **Key Endpoints**: 
  - `GET /secrets` - Fetch secrets using an API key.
  - `POST /api/login` - User authentication.
  - `GET /admin/api/objects` - Admin management of objects.

## Interaction Flow

1. **Secret Fetching**: When an application requests a secret, it sends a GET request to the `/secrets` endpoint with an API key and change number. Aegis verifies the key, enforces policies, and fetches the secrets from the appropriate vault.

2. **Logging**: Every action taken through Aegis is logged in an immutable audit log, capturing details such as the team identity, registry accessed, and objects fetched.

3. **Self-Service Management**: Teams can manage their own webhook subscriptions, notification channels, and CI/CD key rotations through a dedicated dashboard, reducing the need for security team intervention.

4. **Key Rotation**: CI/CD pipelines can trigger key rotations via auto-generated inbound webhook URLs, allowing for automated management of secrets without manual oversight.

## Conclusion

Aegis's architecture is designed to provide a secure, scalable, and user-friendly solution for managing secrets across multiple vaults. By centralizing access and logging, it simplifies the complexities associated with secret management while empowering teams to operate independently.
