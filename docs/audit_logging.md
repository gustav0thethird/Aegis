# Audit and Change Logging

Aegis provides comprehensive audit logging features that ensure every action taken within the system is logged, attributed, and queryable. This functionality is crucial for maintaining security and compliance, allowing teams to monitor and review changes effectively.

## Overview

Aegis logs every interaction with the secrets infrastructure, capturing essential details about each action. This includes:

- **Team Identity**: The team that initiated the action.
- **Registry Accessed**: The specific secrets registry from which secrets were fetched.
- **Objects Fetched**: A list of the secrets that were accessed.
- **Source IP**: The IP address from which the request originated.
- **Change Number**: An identifier for tracking changes associated with IT Service Management (ITSM).

These logs are immutable and structured, providing before-and-after diffs for configuration changes, which enhances traceability and accountability.

## Logging Mechanisms

### Audit Logs

Audit logs capture detailed records of actions performed within Aegis. Each entry includes:

- **Timestamp**: When the action occurred.
- **Action**: The specific operation performed (e.g., fetch, rotate).
- **Entity Type**: The type of entity affected (e.g., secret, configuration).
- **Entity ID**: The unique identifier of the entity.
- **Performed By**: The user or system that executed the action.
- **Outcome**: The result of the action (success or failure).

These logs can be accessed through the admin API, allowing administrators to filter and paginate through entries based on various criteria.

### Change Logs

Change logs track modifications made to the configuration and settings within Aegis. Each log entry includes:

- **Action**: The type of change made (e.g., update, delete).
- **Entity Type**: The type of entity that was changed.
- **Entity ID**: The unique identifier of the changed entity.
- **Detail**: A description of the change.
- **Diff**: The differences before and after the change.

Similar to audit logs, change logs are accessible via the admin API, enabling administrators to review changes over time and maintain an accurate history of modifications.

## Accessing Logs

Logs can be accessed through the following endpoints in the Aegis admin API:

- **Audit Log**: `/admin/api/audit`
- **Change Log**: `/admin/api/changelog`

Both endpoints support pagination and filtering options, allowing users to retrieve specific log entries based on parameters such as entity type, entity ID, action, and more.

## Security and Compliance

The logging features in Aegis are designed to support security and compliance requirements. By maintaining a detailed record of all actions, organizations can ensure accountability and facilitate audits. The structured nature of the logs allows for easy integration with Security Information and Event Management (SIEM) systems, enhancing the overall security posture of the organization.

In summary, Aegis's audit and change logging capabilities provide a robust framework for monitoring actions, ensuring compliance, and maintaining security across the secrets management lifecycle.
