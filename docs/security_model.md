# Security Model

## Overview

The security model of Aegis is designed to ensure secure access to secrets while maintaining a clear audit trail and enabling team autonomy. This model encompasses authentication, authorization, and various protection mechanisms to safeguard sensitive data.

## Authentication

Aegis employs a session-based authentication mechanism. Users authenticate using a username and password, which are verified against stored credentials. Upon successful login, a session token is generated, allowing the user to interact with the Aegis API without needing to re-enter credentials for a specified duration.

- **Login Endpoint**: Users can log in via the `/api/login` endpoint, where their credentials are validated. If valid, a session token is created.
- **Logout Endpoint**: Users can log out via the `/api/logout` endpoint, which invalidates the session token.
- **User Information**: The `/api/me` endpoint provides users with their profile information, including roles and team memberships.

## Authorization

Aegis implements a scoped API key system that ties access to specific teams and registries. Each API key is unique to a team-registry pair, ensuring that teams can only access the secrets they are authorized to see.

- **Scoped API Keys**: Each team is assigned a unique API key for accessing secrets, which limits exposure in case of a key compromise.
- **Multi-Team Membership**: Users can belong to multiple teams, allowing for flexible access control while maintaining strict boundaries on secret visibility.

## Protection Mechanisms

Aegis incorporates several mechanisms to protect against unauthorized access and potential vulnerabilities:

1. **Immutable Logging**: Every action taken through the Aegis API is logged with detailed information, including the team identity, registry accessed, objects fetched, source IP, and change numbers. This ensures accountability and traceability.

2. **Webhook Security**: Aegis validates user-supplied URLs for webhooks to prevent Server-Side Request Forgery (SSRF) attacks. The validation process checks the scheme and host against an allowlist, ensuring that only authorized endpoints can be contacted.

3. **Rate Limiting**: Aegis implements rate limiting to prevent abuse of the API, ensuring that no single user or team can overwhelm the system with requests.

4. **Session Management**: Sessions are managed with a time-to-live (TTL) setting, after which tokens expire, requiring re-authentication. This limits the window of opportunity for an attacker to exploit a compromised token.

5. **Environment Configuration**: Aegis allows for configuration of security settings via environment variables, enabling administrators to customize security policies according to organizational needs.

6. **DNS Rebinding Protection**: Aegis employs DNS pinning to mitigate risks associated with DNS rebinding attacks, ensuring that requests are made to the intended destination.

## Conclusion

The security model of Aegis is built to provide robust protection for sensitive secrets while allowing teams to operate independently. Through a combination of authentication, authorization, and protective measures, Aegis ensures that access to secrets is both secure and auditable.
