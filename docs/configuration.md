# Configuration

This document outlines the configuration options available for Aegis, including environment variables and vendor-specific settings.

## auth.json

The `auth.json` file is used to configure authentication settings for Aegis. It defines the API keys and associated team-registry pairs. Each entry in this file should follow the structure:

```json
{
  "api_keys": {
    "team_name": {
      "registry": "registry_name",
      "key": "api_key_value"
    }
  }
}
```

Ensure that the API keys are unique and scoped to the appropriate teams and registries.

## Vendor Configuration Reference

Aegis supports multiple secret management vendors. Each vendor may have specific configuration requirements. Below are the general settings that can be configured for each vendor:

- **CyberArk**
  - `cyberark_url`: URL of the CyberArk instance.
  - `cyberark_app_id`: Application ID used for authentication.

- **HashiCorp Vault**
  - `vault_address`: Address of the Vault server.
  - `vault_token`: Token for authenticating with Vault.

- **AWS Secrets Manager**
  - `aws_region`: AWS region where the secrets are stored.
  - `aws_access_key_id`: Access key ID for AWS.
  - `aws_secret_access_key`: Secret access key for AWS.

- **Conjur**
  - `conjur_url`: URL of the Conjur instance.
  - `conjur_account`: Conjur account name.
  - `conjur_appliance_url`: URL of the Conjur appliance.

Ensure that the configuration for each vendor is correctly set to enable Aegis to interact with the respective secret management systems.

## Environment Variables

Aegis can be configured using environment variables. Below are the key environment variables that can be set:

- `ESO_ALLOW_REGISTRY_EXTRACT`: Controls whether the `/eso/v1/secrets` endpoint can hand a workload an entire registry. Defaults to `true`.
- `SESSION_TTL_HOURS`: Specifies the session time-to-live in hours. Default is set to `24`.
- `CHANGE_NUMBER_REQUIRED`: Indicates whether a change number is required for API requests. Defaults to `true`.
- `RATE_LIMIT_RPM`: Sets the rate limit in requests per minute. Default is `60`.
- `LOG_RETENTION_DAYS`: Defines the number of days to retain logs. Default is `30`.

These environment variables can be set in your deployment environment to customize the behavior of Aegis.

## Runtime Settings

Aegis allows for runtime configuration through its admin API. The following settings can be modified:

- **SIEM Destinations**
  - `siem_destinations`: List of destinations for sending SIEM events.

- **Logging Configuration**
  - `s3_log_bucket`: S3 bucket for storing logs.
  - `splunk_hec_url`: URL for sending logs to Splunk.
  - `splunk_hec_token`: Token for authenticating with Splunk.

- **Rate Limiting**
  - `rate_limit_rpm`: Maximum requests allowed per minute.

- **Session Management**
  - `session_ttl_hours`: Duration for which a session remains valid.

- **Log Retention**
  - `log_retention_days`: Duration for which logs are retained.

These settings can be accessed and modified through the admin API, allowing for dynamic configuration without requiring a restart of the Aegis service.
