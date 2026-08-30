# Configuration

This document provides details on configuring Aegis, including environment variables, runtime settings, and vendor configurations.

## auth.json

The `auth.json` file is essential for defining the authentication settings for Aegis. It specifies the API keys and their associated permissions. Each entry in this file should map a specific API key to a team and its allowed actions.

### Example Structure
```json
{
  "api_keys": {
    "sk_teamA_registry1": {
      "team": "teamA",
      "registry": "registry1",
      "permissions": ["read", "write"]
    },
    "sk_teamB_registry2": {
      "team": "teamB",
      "registry": "registry2",
      "permissions": ["read"]
    }
  }
}
```

## Vendor Configuration Reference

Aegis supports multiple secret management vendors. Each vendor may require specific configurations to connect and authenticate. Below are the general configurations for supported vendors:

### CyberArk
- **API URL**: The endpoint to access CyberArk.
- **Credentials**: API key or username/password for authentication.

### HashiCorp Vault
- **API URL**: The Vault server URL.
- **Token**: The authentication token for accessing secrets.

### AWS Secrets Manager
- **Region**: The AWS region where the secrets are stored.
- **Access Key ID**: AWS access key for authentication.
- **Secret Access Key**: AWS secret key for authentication.

### Conjur
- **API URL**: The endpoint for Conjur.
- **Account**: The Conjur account name.
- **API Key**: The API key for authentication.

## Environment Variables

Aegis uses several environment variables to configure its runtime behavior. Below is a list of important environment variables:

- **DATABASE_URL**: Connection string for the PostgreSQL database.
- **REDIS_URL**: Connection string for the Redis instance.
- **AUTH_PATH**: Path to the `auth.json` file.
- **ADMIN_PASSWORD**: Password for the admin interface.
- **SECRET_KEY**: Secret key used for cryptographic operations.
- **RATE_LIMIT_RPM**: Rate limit for requests per minute.
- **LOG_DESTINATIONS**: Where to send logs (e.g., stdout, file, etc.).

### Example
```bash
export DATABASE_URL="postgresql://broker:changeme@localhost:5432/aegis"
export REDIS_URL="redis://localhost:6379"
export AUTH_PATH="/config/auth.json"
export ADMIN_PASSWORD="your_admin_password"
export SECRET_KEY="your_secret_key"
export RATE_LIMIT_RPM=60
export LOG_DESTINATIONS="stdout"
```

## Runtime Settings

Aegis can be configured with various runtime settings that control its behavior. These settings can be adjusted in the `docker-compose.yml` file or through environment variables.

### Key Runtime Settings
- **Health Checks**: Ensure that the services are running correctly.
- **Service Dependencies**: Define dependencies between services (e.g., Aegis depends on PostgreSQL and Redis).
- **Ports**: Configure the ports on which Aegis will listen for incoming requests.

### Example Configuration in `docker-compose.yml`
```yaml
services:
  broker:
    build: .
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgresql://broker:changeme@postgres:5432/aegis
      REDIS_URL: redis://redis:6379
      AUTH_PATH: /config/auth.json
      ADMIN_PASSWORD: changeme
      SECRET_KEY: dev-secret-replace-in-prod
      RATE_LIMIT_RPM: 60
      LOG_DESTINATIONS: stdout
```

This configuration sets up Aegis to connect to a PostgreSQL database and a Redis instance, while also specifying the authentication path and other runtime parameters. Adjust these settings according to your deployment environment and requirements.
