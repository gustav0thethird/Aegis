# Configuration

## Configuration Files

### `.env.example`
This file serves as a template for environment variables required for the application. It is not used directly but should be copied to a `.env` file and modified to suit your environment.

### `config/auth.json.example`
This file is an example of the authentication configuration required by the application. It should be copied to `config/auth.json` and populated with the necessary credentials.

## Environment Variables

The application relies on several environment variables for configuration. Below are the key variables and their purposes:

- `DATABASE_URL`: Specifies the connection string for the PostgreSQL database. Example:
  ```
  postgresql://<username>:<password>@<host>:<port>/<database>
  ```

- `ADMIN_PASSWORD`: Sets the password for the admin user.

- `SECRET_KEY`: A secret key used for cryptographic signing. It should be a long, random string.

- `AUTH_PATH`: Path to the authentication configuration file. Default is `config/auth.json`.

- `REDIS_URL`: Specifies the connection string for the Redis service. Example:
  ```
  redis://<host>:<port>
  ```

## GitHub Actions Configuration

### CI Workflow (`.github/workflows/ci.yml`)
The CI workflow is configured to run on pushes and pull requests to specific branches. It includes jobs for linting, testing, and Helm chart validation. The following environment variables are set during the test job:

- `DATABASE_URL`: Set to connect to a test database.
- `ADMIN_PASSWORD`: Used for the admin user during tests.
- `SECRET_KEY`: A test secret key.
- `AUTH_PATH`: Points to the authentication configuration for tests.
- `REDIS_URL`: Connection string for Redis during tests.

### Secret Scanning Workflow (`.github/workflows/secret-scan.yml`)
This workflow is designed to scan for secrets in the repository. It requires the following inputs:

- `aegis-url`: Base URL of the Aegis deployment.
- `team-id`: Aegis team UUID that owns the repository.
- `fail-on-findings`: Boolean to determine if the job should fail when a secret is detected.
- `semgrep-config`: Path to the Semgrep ruleset.

It also requires a secret:

- `aegis-token`: The team's Aegis inbound webhook secret.

## Additional Notes
Ensure that all required environment variables are set before running the application. The `.env` file should not be committed to version control to avoid exposing sensitive information.
