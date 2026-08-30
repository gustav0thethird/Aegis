# Testing

## Guidelines for Testing Aegis

### Test Environment Setup

1. **Database Configuration**: 
   - Ensure that the PostgreSQL database `aegis_test` is accessible. Set the environment variable `TEST_DATABASE_URL` if needed.
   - For local development, run `make test-db` to create the `aegis_test` database in the development PostgreSQL container.

2. **Environment Variables**: 
   - The following environment variables should be set before running tests:
     - `DATABASE_URL`: Points to the test database.
     - `ADMIN_PASSWORD`: Admin password for tests.
     - `SECRET_KEY`: A 32-character secret key.
     - `AUTH_PATH`: Path to the authentication configuration.
     - `REDIS_URL`: URL for Redis.
     - `SCHEDULER_ENABLED`: Set to `false` to prevent background jobs from running during tests.
     - `ALERT_DISPATCH_MODE`: Set to `sync` to ensure alerts are delivered synchronously.

### Running Tests

- To run the tests, execute the following command:
  ```
  make test
  ```

### Test Types

1. **Unit Tests**: 
   - These tests do not require a database and can be run independently. Examples include tests for `test_policy`, `test_broker`, and `test_rate_limit`.

2. **Integration Tests**: 
   - These tests require a running PostgreSQL instance and are designed to test the interactions between components. Examples include tests for `test_secrets` and `test_admin_auth`.

### Test Structure

- Tests are located in the `tests` directory and are organized by functionality:
  - `test_admin_auth.py`: Tests for admin authentication.
  - `test_alerting.py`: Tests for alerting mechanisms.
  - `test_broker.py`: Tests for broker functionalities.
  - `test_eso.py`: Tests for External Secrets Operator endpoints.
  - `test_inbound_webhook.py`: Tests for the inbound webhook receiver.

### Fixtures

- Shared fixtures are defined in `tests/conftest.py`:
  - `_schema`: Creates and drops the database schema for the test session.
  - `client`: Provides a session-scoped TestClient for making requests to the API.
  - `db`: Provides a function-scoped session for direct database interactions in integration tests.

### Example Test Execution

- To run a specific test file, use:
  ```
  pytest tests/test_admin_auth.py
  ```

### Mocking External Dependencies

- Use mocking for external services such as network calls or email services to ensure tests run in isolation and do not depend on external systems.

### Code Coverage

- Ensure that tests cover all critical paths and edge cases to maintain code quality and reliability.

By following these guidelines, you can effectively test the Aegis application and ensure its functionality and reliability.
