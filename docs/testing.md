# Testing

## Guidelines for Testing Aegis

This document outlines the guidelines for setting up and running tests for the Aegis project.

### Setup

1. **Database Configuration**:
   - Ensure that PostgreSQL is installed and running.
   - Set the environment variable `TEST_DATABASE_URL` to point to your test database, or ensure that the default `aegis_test` database is reachable.

2. **Environment Variables**:
   - The following environment variables must be set before running tests:
     - `DATABASE_URL`: Set to `postgresql://broker:changeme@localhost:5432/aegis_test`.
     - `ADMIN_PASSWORD`: Set to `test-admin-pass`.
     - `SECRET_KEY`: Set to `test-secret-key-32-chars-xyzxyzxy`.
     - `AUTH_PATH`: Set to `config/auth.json`.
     - `REDIS_URL`: Set to `redis://localhost:6379`.
     - `SCHEDULER_ENABLED`: Set to `false` to prevent the background job from running during tests.
     - `ALERT_DISPATCH_MODE`: Set to `sync` to ensure alerts are delivered synchronously.

3. **Test Database Creation**:
   - For local development, run the command:
     ```bash
     make test-db
     ```
   - This command will create the `aegis_test` database in the development PostgreSQL container.

### Running Tests

1. **Unit Tests**:
   - Unit tests do not require a database and can be run directly using:
     ```bash
     make test
     ```

2. **Integration Tests**:
   - Integration tests require a PostgreSQL database and can also be run using the same command:
     ```bash
     make test
     ```

3. **Test Client**:
   - The test suite uses a `TestClient` to simulate requests to the Aegis API. This client is configured to use a fresh database session for each request.

### Fixtures

- **Schema Fixture**: Creates and drops the database schema for the test session.
- **Client Fixture**: Provides a session-scoped `TestClient` for making requests.
- **Database Fixture**: Provides a function-scoped session for direct database access in integration tests.

### Test Structure

- Tests are organized into various files under the `tests` directory, each focusing on different components of the Aegis application.
- Common test files include:
  - `test_admin_auth.py`: Tests for admin authentication.
  - `test_alerting.py`: Tests for alerting functionality.
  - `test_broker.py`: Tests for broker-related functionality.
  - `test_eso.py`: Tests for External Secrets Operator endpoints.
  - `test_inbound_webhook.py`: Tests for the inbound webhook receiver.

### Running Tests in CI

- Continuous Integration (CI) workflows are defined in the `.github/workflows` directory, which automatically provision a PostgreSQL service container for running tests.

By following these guidelines, you can effectively set up and run tests for the Aegis project, ensuring that the application functions as intended.
