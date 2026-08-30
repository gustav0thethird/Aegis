# Security Model

## Overview

The security model implemented in Aegis focuses on robust authentication, authorization, and protection mechanisms to ensure secure access to secrets. Aegis serves as a vendor-agnostic secrets broker and PAM gateway, allowing teams to manage their own access to secrets while maintaining strict security controls.

## Authentication

Aegis employs a session-based authentication mechanism. Users authenticate by providing a username and password, which are verified against stored credentials. Upon successful authentication, a session token is generated, allowing users to interact with the Aegis API securely.

- **Login Endpoint**: Users can log in via the `/api/login` endpoint, which validates credentials and returns a session token.
- **Logout Endpoint**: Users can log out via the `/api/logout` endpoint, which invalidates the session token.
- **User Information Retrieval**: The `/api/me` endpoint allows users to retrieve their profile information, including roles and team memberships, using the session token.

## Authorization

Authorization in Aegis is managed through scoped API keys. Each team is assigned a unique API key that is tied to specific registries. This ensures that teams can only access the secrets they are authorized to see.

- **Scoped API Keys**: Each API key is scoped to a specific team-registry pair, limiting access to secrets based on team membership.
- **Multi-Team Membership**: Users can belong to multiple teams, and authorization checks are performed to ensure that access is granted only to the appropriate secrets.

## Protection Mechanisms

Aegis implements several protection mechanisms to safeguard against unauthorized access and potential attacks:

1. **Session Management**: Sessions are created with a time-to-live (TTL) to limit the duration of access. Tokens are invalidated upon logout or expiration.
  
2. **Rate Limiting**: Aegis includes rate limiting to prevent abuse of the API and to mitigate denial-of-service attacks.

3. **Webhook Security**: Aegis validates user-supplied outbound URLs to prevent Server-Side Request Forgery (SSRF) attacks. The validation process ensures that only allowed schemes and hosts are accepted for webhook notifications.

4. **Audit Logging**: Every action taken within Aegis is logged, including API requests, secret fetches, and configuration changes. This logging includes details such as team identity, registry accessed, and source IP, ensuring full accountability and traceability.

5. **Change Management**: Aegis enforces policies around change management, requiring change numbers and validating requests based on time windows and IP addresses.

6. **Immutable Logs**: All logs are immutable, providing a reliable audit trail for security reviews and compliance purposes.

7. **SIEM Integration**: Aegis can emit events to Security Information and Event Management (SIEM) systems for real-time monitoring and alerting.

By combining these authentication, authorization, and protection mechanisms, Aegis ensures a secure environment for managing sensitive secrets across multiple teams and registries.
