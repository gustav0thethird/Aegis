# Deployment

This document provides guidelines for deploying Aegis in various environments, specifically focusing on Kubernetes and AWS.

## Kubernetes Deployment

Aegis can be deployed on Kubernetes using Helm. The following steps outline the deployment process:

1. **Install Helm**: Ensure that Helm is installed on your local machine. You can follow the [Helm installation guide](https://helm.sh/docs/intro/install/) for instructions.

2. **Add Aegis Helm Repository**:
   ```bash
   helm repo add aegis https://github.com/gustav0thethird/Aegis
   helm repo update
   ```

3. **Deploy Aegis**:
   Use the following command to install Aegis:
   ```bash
   helm install aegis aegis/aegis
   ```

4. **Configuration**:
   You can customize the deployment by providing a `values.yaml` file. This file can include configurations for environment variables, resource limits, and other settings specific to your deployment.

5. **Accessing Aegis**:
   After deployment, you can access Aegis through the service created by Helm. Use `kubectl get services` to find the external IP or service name.

6. **Monitoring and Logging**:
   Ensure that you have monitoring and logging set up for your Kubernetes cluster to track the performance and health of the Aegis deployment.

## AWS Deployment

Aegis can also be deployed on AWS using Terraform. The following steps outline the deployment process:

1. **Prerequisites**:
   - Ensure you have Terraform installed. Follow the [Terraform installation guide](https://www.terraform.io/downloads.html) for instructions.
   - Configure your AWS credentials.

2. **Clone the Repository**:
   Clone the Aegis repository to your local machine:
   ```bash
   git clone https://github.com/gustav0thethird/Aegis.git
   cd Aegis/terraform
   ```

3. **Configure Variables**:
   Edit the `variables.tf` file to set your AWS region, application name, and other necessary configurations.

4. **Initialize Terraform**:
   Run the following command to initialize Terraform:
   ```bash
   terraform init
   ```

5. **Plan the Deployment**:
   Generate an execution plan:
   ```bash
   terraform plan
   ```

6. **Apply the Deployment**:
   Deploy Aegis to AWS:
   ```bash
   terraform apply
   ```

7. **Accessing Aegis**:
   After deployment, you can access Aegis via the Application Load Balancer (ALB) created by Terraform. The ALB DNS name will be outputted after the `terraform apply` command completes.

8. **Monitoring and Logging**:
   Ensure that you have AWS CloudWatch set up for monitoring logs and metrics related to the Aegis deployment.

## Additional Considerations

- **Security**: Ensure that IAM roles and policies are correctly configured to allow Aegis to access necessary AWS resources, such as Secrets Manager and S3.
- **Scaling**: Both Kubernetes and AWS deployments should be monitored for scaling needs based on the number of teams and secrets being managed.
- **Backup and Recovery**: Implement a backup strategy for your Aegis deployment to ensure data integrity and availability.

By following these guidelines, you can successfully deploy Aegis in your chosen environment.
