# Aegis — Cloud & Hybrid Deployment

## Cloud Deployment (AWS)

The Terraform configuration in `terraform/` provisions a fully managed, HA AWS stack:

| Component | AWS Service |
|-----------|-------------|
| Application | ECS Fargate (2 tasks, private subnets) |
| Database | Aurora PostgreSQL 16 (writer + reader) |
| Cache | ElastiCache Redis 7 |
| TLS + routing | ALB + ACM certificate |
| Secrets | AWS Secrets Manager |
| Logs | CloudWatch Logs |
| Images | ECR |

### Prerequisites

- Terraform >= 1.5
- AWS CLI configured (`aws configure`)
- Docker (to build and push the image)
- A domain name you control (for ACM certificate DNS validation)

### Deploy

```bash
# 1. Build and push the image to ECR
#    (create the ECR repo first via the console or terraform apply -target)
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

docker build -t aegis:latest .
docker tag aegis:latest <account>.dkr.ecr.us-east-1.amazonaws.com/aegis:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/aegis:latest

# 2. Configure auth.json as a Secrets Manager secret
#    (the ECS task expects it at /config/auth.json — for cloud, mount via ECS volume
#     or encode it into a Secrets Manager secret and reference in ecs.tf)
aws secretsmanager create-secret \
  --name aegis/prod/auth-json \
  --secret-string "$(cat config/auth.json)"

# 3. Initialise Terraform
make tf-init

# 4. Review the plan
make tf-plan

# 5. Apply
#    You will be prompted for: image_uri, domain_name, admin_password, secret_key
make tf-apply
```

### DNS validation

After `terraform apply`, Terraform outputs the CNAME records needed to validate your ACM certificate:

```
acm_validation_records = {
  "aegis.example.com" = {
    name  = "_abc123.aegis.example.com"
    type  = "CNAME"
    value = "_xyz456.acm-validations.aws"
  }
}
```

Add these to your DNS provider. ACM validation completes within a few minutes.
Then re-run `terraform apply` to complete the `aws_acm_certificate_validation` resource.

### Point your domain

```bash
terraform output alb_dns_name
# → aegis-prod-alb-1234567890.us-east-1.elb.amazonaws.com
```

Add a CNAME record in your DNS: `aegis.yourdomain.com → <alb_dns_name>`

### CI/CD deployments

The ECS service is configured with `ignore_changes = [task_definition]` so Terraform won't
roll back image updates made outside of it. To deploy a new image:

```bash
# Build, push, then force a new deployment
docker build -t <ecr-uri>:$GIT_SHA .
docker push <ecr-uri>:$GIT_SHA

aws ecs update-service \
  --cluster aegis-prod-cluster \
  --service aegis-prod-broker \
  --force-new-deployment
```

Migrations run automatically on container start via `alembic upgrade head` in the `CMD`.

### Secrets

All sensitive values are stored in AWS Secrets Manager and injected into the ECS task at runtime.
The application never sees them as environment variables in the task definition — they're resolved
by the ECS agent.

To rotate the admin password:
```bash
aws secretsmanager put-secret-value \
  --secret-id aegis/prod/admin-password \
  --secret-string "newpassword"

aws ecs update-service --cluster aegis-prod-cluster --service aegis-prod-broker --force-new-deployment
```

### Teardown

```bash
make tf-destroy
```

> Aurora has `deletion_protection = true`. You must disable it manually in the console
> before destroy will succeed. This is intentional.

---

## Hybrid Deployment

The most common real-world pattern for a secrets broker: **Aegis runs in cloud, secret stores stay on-prem.**

```
┌─────────────────────────────────────────────────────────────┐
│  Cloud (AWS / GCP / Azure)                                  │
│                                                             │
│   Applications  ──▶  Aegis Broker (ECS / K8s / VPS)        │
│   CI/CD pipelines         │                                 │
│                           │ auth.json credentials           │
└───────────────────────────┼─────────────────────────────────┘
                            │  VPN / Direct Connect / Peering
┌───────────────────────────┼─────────────────────────────────┐
│  On-premises              │                                 │
│                           ▼                                 │
│   CyberArk PAM  ◀──  backend fetch                         │
│   HashiCorp Vault ◀──                                       │
│   Conjur          ◀──                                       │
└─────────────────────────────────────────────────────────────┘
```

Aegis is stateless with respect to secrets — it never caches credentials, only fetches on demand.
This means it can live anywhere that has network access to the backend stores.

### Network connectivity options

| Option | Best for |
|--------|----------|
| **Site-to-site VPN** | Most common. AWS VPN Gateway or equivalent. Low cost, easy to set up. |
| **AWS Direct Connect** | High throughput or latency-sensitive environments. |
| **VPC Peering / Transit Gateway** | If your on-prem infrastructure uses a cloud-connected private network. |
| **Reverse tunnel (e.g. Tailscale)** | Smaller setups or dev/staging where a VPN gateway is overkill. |

### auth.json in hybrid deployments

`auth.json` contains the credentials Aegis uses to authenticate against your backend secret stores.
In a hybrid setup these are on-prem service account credentials (CyberArk app ID, Vault token, etc.).

**Do not commit auth.json.** In cloud deployments, inject it via:

- **ECS**: store as a Secrets Manager secret, mount as an EFS volume or reference in the task definition
- **Kubernetes**: store as a Kubernetes Secret, mount as a volume at `/config/auth.json`
- **Single-server**: mount the file via Docker volume, keep it outside the repo

### Security considerations

In a hybrid deployment, the broker is the only component that needs network access to your secret stores.
Applications never get direct access — they only get the fetched value via `/secrets`, scoped to their
registered team and registry.

- **Least privilege**: the service account in `auth.json` should have read-only access to exactly the
  paths referenced by your objects. No write access, no admin access.
- **mTLS**: if your backend (Vault, CyberArk) supports mutual TLS, enable `cn_required` in the
  registry policy and pass the client certificate CN via `X-TLS-Client-CN`.
- **IP allowlist**: restrict which CIDR blocks can call `/secrets` via the registry or team policy.
  In a cloud deployment, this is typically your application subnet range.
- **Audit log forwarding**: set `LOG_DESTINATIONS=stdout,siem` and forward CloudWatch / container logs
  to your on-prem SIEM. Every fetch is logged with team, registry, change number, and source IP.

### Example: Vault on-prem, Aegis on AWS

```json
// config/auth.json
{
  "prod-vault": {
    "type": "vault",
    "url": "https://vault.internal.example.com",
    "token": "s.xxxxxxxxxxxx"
  }
}
```

Vault lives on-prem. Aegis lives in ECS. The VPN handles routing.
Applications in AWS call `GET /secrets` — they never touch Vault directly.

To restrict which apps can do this, set an IP allowlist policy on the registry:

```bash
curl -X PUT https://aegis.example.com/admin/api/registries/<id>/policy \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"ip_allowlist": ["10.0.3.0/24", "10.0.4.0/24"]}'
```
