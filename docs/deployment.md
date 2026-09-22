# Deployment

This document provides guidelines for deploying Aegis in various environments, including Docker, Helm, and Terraform configurations.

## Docker Deployment

Aegis can be deployed using Docker by utilizing the provided `docker-compose.yml` file. This file defines the necessary services, including PostgreSQL, Redis, and the Aegis broker.

### Steps to Deploy with Docker

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/gustav0thethird/Aegis.git
   cd Aegis
   ```

2. **Set Environment Variables**:
   You can set environment variables in a `.env` file or directly in your shell. The following variables are available:
   - `POSTGRES_DB`: Database name (default: `aegis`)
   - `POSTGRES_USER`: Database user (default: `broker`)
   - `POSTGRES_PASSWORD`: Database password (default: `changeme`)
   - `ADMIN_PASSWORD`: Admin password (leave unset for random generation)
   - `SECRET_KEY`: Secret key for the application (default: `dev-secret-replace-in-prod`)
   - `RATE_LIMIT_RPM`: Rate limit in requests per minute (default: `60`)
   - `LOG_DESTINATIONS`: Log destinations (default: `stdout`)

3. **Start the Services**:
   Run the following command to start all services defined in the `docker-compose.yml`:
   ```bash
   docker-compose up -d
   ```

4. **Access Aegis**:
   Aegis will be accessible at `http://localhost:8080`.

5. **Check Service Health**:
   Ensure that all services are healthy by checking their logs:
   ```bash
   docker-compose logs
   ```

## Helm Deployment

For Kubernetes environments, Aegis can be deployed using Helm. Ensure you have Helm installed and configured to communicate with your Kubernetes cluster.

### Steps to Deploy with Helm

1. **Add the Aegis Helm Repository**:
   ```bash
   helm repo add aegis https://github.com/gustav0thethird/Aegis
   helm repo update
   ```

2. **Install Aegis**:
   You can install Aegis with the following command:
   ```bash
   helm install aegis aegis/aegis
   ```

3. **Configure Values**:
   You can customize the deployment by creating a `values.yaml` file. This file can include configurations for database settings, Redis settings, and other environment variables.

4. **Upgrade Aegis**:
   If you need to update your deployment, modify the `values.yaml` file and run:
   ```bash
   helm upgrade aegis aegis/aegis -f values.yaml
   ```

## Terraform Deployment

Aegis can also be deployed using Terraform, specifically for AWS infrastructure. The provided `terraform/main.tf` file sets up the foundational AWS infrastructure, including VPC, subnets, internet and NAT gateways, route tables, and security groups.

### Steps to Deploy with Terraform

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/gustav0thethird/Aegis.git
   cd Aegis/terraform
   ```

2. **Configure Variables**:
   Create a `terraform.tfvars` file to specify your variables:
   ```hcl
   app_name = "aegis"
   environment = "production"
   vpc_cidr = "10.0.0.0/16"
   aws_region = "us-west-2"
   ```

3. **Initialize Terraform**:
   Run the following command to initialize Terraform:
   ```bash
   terraform init
   ```

4. **Plan the Deployment**:
   Generate an execution plan:
   ```bash
   terraform plan
   ```

5. **Apply the Deployment**:
   Deploy the infrastructure:
   ```bash
   terraform apply
   ```

6. **Access Aegis**:
   After deployment, configure your application to connect to the Aegis service using the provided endpoints.

## Conclusion

This document outlines the basic steps for deploying Aegis in Docker, Helm, and Terraform environments. Ensure to review the configurations and customize them according to your specific requirements.
