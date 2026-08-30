# Team Self-Service Model

Aegis provides a self-service model that empowers teams to manage their own webhook subscriptions, key rotations, and notifications without needing to file tickets with the security team. This model is designed to streamline operations and enhance efficiency by allowing teams to take direct control over their interactions with the secrets management system.

## Webhook Subscriptions

Teams can configure their own webhook subscriptions to receive notifications about various events related to their secrets. This includes updates on key rotations, access logs, and other relevant changes. The self-service API allows teams to:

- Create, update, and delete webhook subscriptions.
- Specify the events they want to be notified about.
- Manage the endpoints to which notifications are sent.

This capability ensures that teams are immediately informed of any changes that may affect their operations, allowing for timely responses to potential issues.

## Key Rotation

Key rotation is a critical aspect of maintaining security in any secrets management system. Aegis allows teams to manage their own key rotations through a self-service interface. Teams can:

- Initiate key rotations for their scoped API keys.
- Set up automatic key rotations triggered by CI/CD pipelines via inbound webhooks.
- View the status and history of key rotations for their keys.

By enabling teams to handle key rotations independently, Aegis reduces the burden on the security team and minimizes the risk of key-related incidents.

## Team Dashboard

Each team has access to a dedicated dashboard that provides an overview of their secrets, active keys, and webhook subscriptions. The dashboard includes:

- A list of active keys and their expiration dates.
- Details about the registries the team has access to.
- A summary of webhook subscriptions and their statuses.

This centralized view allows teams to easily manage their secrets and stay informed about their security posture.

## Conclusion

The self-service capabilities in Aegis are designed to enhance operational efficiency and security by allowing teams to manage their own webhook subscriptions and key rotations. This model not only empowers teams but also ensures that the security team can focus on policy management rather than operational tasks.
