# Audit and Change Logging

Aegis provides comprehensive audit logging features that ensure every action taken within the system is recorded, attributed, and can be queried. This functionality is crucial for maintaining security and compliance in managing sensitive secrets.

## Logging Features

### Immutable Logs
Every action performed through Aegis is logged in an immutable format. This includes:

- Fetching secrets
- Rotating keys
- Making configuration changes

Each log entry contains structured before-and-after diffs, allowing for clear visibility into what changes were made.

### Logged Information
The logs capture essential details for each action, including:

- **Team Identity**: The team that performed the action.
- **Registry Accessed**: The specific secrets registry that was accessed.
- **Objects Fetched**: A list of the secrets or objects that were retrieved.
- **Source IP**: The IP address from which the request originated.
- **Change Number**: An ITSM change number associated with the action.

This level of detail ensures that there is no way to fetch a secret without leaving a trace, enhancing accountability and traceability.

## Querying Logs

Aegis provides an API for querying both change logs and audit logs, allowing administrators to filter and paginate through log entries.

### Change Log API
The change log can be accessed via the following endpoint:

```
GET /admin/api/changelog
```

#### Query Parameters
- `page`: The page number for pagination (default is 1).
- `limit`: The number of entries per page (default is 50).
- `entity_type`: Filter by the type of entity changed.
- `entity_id`: Filter by the specific entity ID.
- `action`: Filter by the action performed.

The response includes the total number of entries, the current page, and the rows of log entries.

### Audit Log API
The audit log can be accessed via the following endpoint:

```
GET /admin/api/audit
```

#### Query Parameters
- `page`: The page number for pagination (default is 1).
- `limit`: The number of entries per page (default is 50).
- `registry_id`: Filter by the specific registry ID.
- `change_number`: Filter by the change number associated with the action.
- `outcome`: Filter by the outcome of the action.

Similar to the change log, the audit log response provides pagination details and the relevant log entries.

## Conclusion

The audit logging features of Aegis are designed to provide a robust framework for tracking and managing actions related to secret management. By ensuring that every action is logged with detailed attribution, Aegis enhances security and compliance, making it easier for teams to manage their secrets responsibly.
