# Deployment

This document provides guidelines for deploying Aegis in various environments, including Docker, Helm, and Terraform configurations.

## Docker Deployment

Aegis can be deployed using Docker, which allows for easy setup and management of dependencies. The following `docker-compose.yml` file sets up the necessary services, including PostgreSQL and Redis.

### docker-compose.yml

```yaml
services:
  postgres:
    image: postgres:16-alpine
    command: >
      postgres
        -c shared_preload_libraries=pg_stat_statements
        -c pg_stat_statements.track=all
        -c max_connections=100
    environment:
      POSTGRES_DB:       ${POSTGRES_DB:-aegis}
      POSTGRES_USER:     ${POSTGRES_USER:-broker}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    ports:
      - "5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-broker} -d ${POSTGRES_DB:-aegis}"]
      interval: 5s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

  broker:
    build: .
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL:      postgresql://${POSTGRES_USER:-broker}:${POSTGRES_PASSWORD:-changeme}@postgres:5432/${POSTGRES_DB:-aegis}
      REDIS_URL:         redis://redis:6379
      AUTH_PATH:         /config/auth.json
      ADMIN_PASSWORD:    ${ADMIN_PASSWORD:-changeme}
      SECRET_KEY:        ${SECRET_KEY:-dev-secret-replace-in-prod}
      RATE_LIMIT_RPM:    ${RATE_LIMIT_RPM:-60}
      LOG_DESTINATIONS:  ${LOG_DESTINATIONS:-stdout}
    volumes:
      - ./config:/config
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8080/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 15s

volumes:
  pg_data:
  redis_data:
```

### Steps to Deploy

1. Ensure Docker and Docker Compose are installed on your machine.
2. Clone the Aegis repository.
3. Navigate to the directory containing the `docker-compose.yml` file.
4. Run `docker-compose up` to start the services.

## Helm Deployment

Aegis can also be deployed using Helm, which simplifies the management of Kubernetes applications. The following `Chart.yaml` file defines the Helm chart metadata for Aegis.

### helm/Chart.yaml

```yaml
apiVersion: v2
name: aegis
description: Aegis — Vault Agnostic API Broker Solution
type: application
version: 0.1.0
appVersion: "0.1.0"
home: https://github.com/gustav0thethird/Aegis
sources:
  - https://github.com/gustav0thethird/Aegis
keywords:
  - secrets
  - vault
  - cyberark
  - conjur
  - external-secrets
maintainers:
  - name: gustav0thethird
```

### Steps to Deploy

1. Ensure Helm is installed and configured to communicate with your Kubernetes cluster.
2. Clone the Aegis repository.
3. Navigate to the directory containing the Helm chart.
4. Run `helm install aegis .` to deploy Aegis.

## Terraform Deployment

Aegis can be provisioned using Terraform, which allows for infrastructure as code. The following `main.tf` file sets up the necessary AWS infrastructure.

### terraform/main.tf

```hcl
locals {
  name = "${var.app_name}-${var.environment}"

  common_tags = {
    App         = var.app_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  azs = [
    "${var.aws_region}a",
    "${var.aws_region}b",
  ]
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 1)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = local.azs[count.index];

  tags = { Name = "${local.name}-private-${count.index + 1}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${local.name}-nat" }
  depends_on    = [aws_internet_gateway.main]
}
```

### Steps to Deploy

1. Ensure Terraform is installed and configured with your AWS credentials.
2. Clone the Aegis repository.
3. Navigate to the directory containing the Terraform configuration.
4. Run `terraform init` to initialize the configuration.
5. Run `terraform apply` to provision the infrastructure.

## Conclusion

This document outlines the deployment options for Aegis using Docker, Helm, and Terraform. Follow the respective steps for each method to successfully deploy Aegis in your environment.
