# Deployment

This document outlines the guidelines for deploying Aegis in various environments, including Docker, Helm, and Terraform configurations.

## Docker Deployment

Aegis can be deployed using Docker by utilizing the provided `docker-compose.yml` file. This file sets up the necessary services, including PostgreSQL and Redis, with default configurations and health checks.

### Steps to Deploy with Docker

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/gustav0thethird/Aegis.git
   cd Aegis
   ```

2. **Build and Start Services**:
   ```bash
   docker-compose up --build
   ```

3. **Access Aegis**:
   Aegis will be accessible at `http://localhost:8080`.

### Configuration

- **PostgreSQL**: The database configuration can be modified in the `docker-compose.yml` file under the `postgres` service.
- **Redis**: Configuration for Redis is also available in the same file under the `redis` service.
- **Broker Service**: The Aegis broker service can be configured with environment variables such as `DATABASE_URL`, `REDIS_URL`, and `ADMIN_PASSWORD`.

## Helm Deployment

Aegis can be deployed on Kubernetes using Helm. The chart lives in `charts/aegis/` and is published as an OCI artifact at `oci://ghcr.io/gustav0thethird/charts/aegis`.

### Steps to Deploy with Helm

1. **Add the Helm Repository**:
   ```bash
   helm repo add aegis https://github.com/gustav0thethird/Aegis
   ```

2. **Install the Chart**:
   ```bash
   helm install aegis aegis/aegis
   ```

3. **Access Aegis**:
   After installation, you can access Aegis using the service created by Helm.

### Configuration

- The Helm chart allows customization through values files. You can specify configurations such as replicas, image tags, and resource limits in a custom `values.yaml` file.

## Terraform Deployment

Aegis can also be deployed using Terraform, which sets up the foundational AWS infrastructure.

### Steps to Deploy with Terraform

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/gustav0thethird/Aegis.git
   cd Aegis/terraform
   ```

2. **Initialize Terraform**:
   ```bash
   terraform init
   ```

3. **Plan the Deployment**:
   ```bash
   terraform plan
   ```

4. **Apply the Configuration**:
   ```bash
   terraform apply
   ```

### Configuration

- The `main.tf` file contains the configuration for the VPC, subnets, internet and NAT gateways, and route tables. You can modify the variables such as `app_name`, `environment`, and `vpc_cidr` to suit your deployment needs.

## Conclusion

This document provides a concise overview of deploying Aegis in different environments. Ensure to review the respective configuration files for customization options based on your specific requirements.
