# Usage

Aegis provides a set of API endpoints for fetching secrets and managing team self-service functionalities. Below is a detailed guide on how to utilize these features effectively.

## API Endpoints

### Secrets Endpoint

The primary endpoint for retrieving secrets is `/secrets`. This endpoint allows authenticated teams to fetch their secrets based on their scoped API key.

#### Request

```http
GET /secrets
X-API-Key: sk_...
X-Change-Number: CHG123
```

#### Parameters

- **X-API-Key**: The API key assigned to the team.
- **X-Change-Number**: An optional change number for tracking changes.

#### Response

On a successful request, the response will contain the requested secrets in JSON format:

```json
{
  "secret_name": "value"
}
```

#### Error Handling

If the API key is invalid or not provided, a `401 Unauthorized` error will be returned.

### User Self-Service API

Aegis also provides endpoints for team self-service functionalities, allowing teams to manage their own webhooks, key rotations, and notifications.

#### Fetching Team Information

To retrieve information about the teams a user belongs to, use the following endpoint:

```http
GET /api/my-teams
```

#### Response

This endpoint returns a JSON object containing details about the teams, including active keys and associated registries.

```json
{
  "id": "team_id",
  "name": "team_name",
  "registries": [
    {
      "id": "registry_id",
      "name": "registry_name",
      "objects": ["object1", "object2"],
      "key_preview": "key_preview",
      "expires_at": "expiration_date"
    }
  ],
  "objects": [
    {
      "name": "object_name",
      "vendor": "vendor_name",
      "path": "object_path",
      "platform": "platform_name",
      "safe": "safe_name"
    }
  ]
}
```

#### Error Handling

If the user is an admin, a `400 Bad Request` error will be returned, as admins should use the admin API.

## Team Self-Service Functionalities

Teams can self-manage various functionalities through their dashboard, including:

- **Webhook Subscriptions**: Teams can create and manage webhooks for notifications.
- **Key Rotation**: Teams can trigger key rotations without requiring admin intervention.
- **Notification Channels**: Teams can configure their preferred notification channels (e.g., Slack, Teams, Discord).

### Managing Webhooks

To manage webhooks, teams can use the relevant endpoints provided in the self-service API. This allows teams to subscribe to events and receive notifications based on their configurations.

### Key Rotation

Key rotations can be triggered directly through CI/CD pipelines using auto-generated inbound webhook URLs. This enables teams to maintain security without needing to involve the security team for every rotation.

## Conclusion

Aegis provides a robust API for managing secrets and team functionalities. By utilizing the `/secrets` endpoint and the self-service API, teams can efficiently handle their secret management needs while maintaining security and compliance.
