# Usage

## API Endpoints

### Health Check
- **GET** `/health`
  - Returns the health status of the service.

### Authentication
- **POST** `/api/login`
  - Request: `{"username": "your_username", "password": "your_password"}`
  - Response: Session token.

- **POST** `/api/logout`
  - Logs out the current session.

- **GET** `/api/me`
  - Returns the current user's information.

- **PUT** `/api/me/theme`
  - Request: `{"theme": "new_theme"}`
  - Updates the user's theme preference.

### User Endpoints (Role: User)
- **GET** `/api/my-teams`
  - Returns the teams the user is a member of.

- **GET** `/api/my-webhook`
  - Returns the user's configured webhook and notification channels.

- **PUT** `/api/my-webhook`
  - Request: `{"url": "webhook_url", "events": ["event1", "event2"], "enabled": true}`
  - Configures the outgoing webhook and notifications.

- **DELETE** `/api/my-webhook`
  - Removes the user's configured webhook.

- **GET** `/api/my-metrics`
  - Returns team-scoped audit counts and key statistics.

- **GET** `/api/my-metrics/prometheus`
  - Returns team-scoped Prometheus metrics for Grafana.

- **POST** `/api/inbound/{team_id}`
  - Request: Inbound webhook receiver for CI/CD trigger.
  - Requires Bearer token as signing secret.

### Admin Endpoints (Role: Admin)
- **GET** `/admin/api/ping`
  - Returns a ping response to check if the admin API is reachable.

- **GET** `/admin/api/objects`
  - Lists all objects.

- **POST** `/admin/api/objects`
  - Request: `{"name": "object_name", "vendor": "vendor_name", "auth_ref": "auth_reference", "path": "object_path"}`
  - Creates a new object.

- **GET** `/admin/api/teams`
  - Lists all teams.

- **POST** `/admin/api/teams`
  - Request: `{"name": "team_name"}`
  - Creates a new team.

- **GET** `/admin/api/users`
  - Lists all users.

- **POST** `/admin/api/users`
  - Request: `{"username": "new_username", "password": "new_password", "role": "user", "team_ids": ["team_id1", "team_id2"], "theme": "default"}`
  - Creates a new user.

- **GET** `/admin/api/changelog`
  - Returns the change log.

- **GET** `/admin/api/audit`
  - Returns the audit log.

### Webhook Management
- **GET** `/admin/api/teams/{team_id}/webhook`
  - Returns the webhook configuration for a specific team.

- **PUT** `/admin/api/teams/{team_id}/webhook`
  - Request: `{"url": "webhook_url", "events": ["event1", "event2"], "enabled": true, "signing_enabled": false}`
  - Configures the webhook for a specific team.

## Examples

### Login Example
```bash
curl -X POST http://localhost:8000/api/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}'
```

### Get User Teams
```bash
curl -X GET http://localhost:8000/api/my-teams -H "Authorization: Bearer your_token"
```

### Create a New Team
```bash
curl -X POST http://localhost:8000/admin/api/teams -H "Authorization: Bearer your_admin_token" -H "Content-Type: application/json" -d '{"name": "new_team"}'
```

### Configure Webhook
```bash
curl -X PUT http://localhost:8000/admin/api/teams/{team_id}/webhook -H "Authorization: Bearer your_admin_token" -H "Content-Type: application/json" -d '{"url": "https://example.com/webhook", "events": ["event1", "event2"], "enabled": true, "signing_enabled": false}'
```

This documentation provides a concise overview of how to use the Aegis API, including available endpoints and example requests.
