# Configuration

## Configuration Files

### `.env.example`
This file serves as a template for environment variables that can be used in the application. It should be copied to `.env` and modified according to your environment settings.

### `config/auth.json.example`
This file is an example of the authentication configuration. It should be copied to `config/auth.json` and populated with the necessary authentication details.

## Environment Variables

The application relies on several environment variables for configuration. Below is a list of the key environment variables and their purposes:

- `DATABASE_URL`: The connection string for the PostgreSQL database. Example:
  ```
  postgresql://<user>:<password>@<host>:<port>/<database>
  ```

- `ADMIN_PASSWORD`: The password for the admin user.

- `SECRET_KEY`: A secret key used for cryptographic signing. It should be a random string of at least 32 characters.

- `AUTH_PATH`: The path to the authentication configuration file. Default is `config/auth.json`.

- `REDIS_URL`: The connection string for the Redis instance. Example:
  ```
  redis://<host>:<port>
  ```

## GitHub Actions Configuration

The CI/CD pipeline is configured using GitHub Actions. The following environment variables are set in the CI workflow:

- `DATABASE_URL`: Used to connect to the test database.
- `ADMIN_PASSWORD`: Used for admin authentication during tests.
- `SECRET_KEY`: Used for signing during tests.
- `AUTH_PATH`: Points to the authentication configuration file for tests.
- `REDIS_URL`: Connection string for Redis during tests.

## Helm Chart Configuration

When deploying with Helm, you can set various values in the `helm/templates` directory. The following values can be configured:

- `auth.existingSecret`: The name of the existing Kubernetes secret that contains authentication details.
- `secret.existingSecret`: The name of the existing Kubernetes secret that contains other sensitive information.
- Additional optional features can be enabled through Helm values, such as ingress, autoscaling, and service monitoring.

## Secret Scanning Configuration

For secret scanning, the following inputs are required when calling the secret scan workflow:

- `aegis-url`: The base URL of the Aegis deployment.
- `team-id`: The UUID of the Aegis team that owns the repository.
- `fail-on-findings`: A boolean to determine if the job should fail when a secret is detected (default is true).
- `semgrep-config`: The Semgrep ruleset to use (default is `p/secrets`).

The following secret is required:

- `aegis-token`: The team's Aegis inbound webhook secret.
