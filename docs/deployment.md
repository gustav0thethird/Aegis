# Deployment

## Local Deployment

To deploy Aegis locally, you can use Docker Compose. Follow these steps:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/gustav0thethird/Aegis.git
   cd Aegis
   ```

2. **Create a `.env` File:**
   Copy the `.env.example` to `.env` and modify the environment variables as needed.

3. **Start the Services:**
   Run the following command to start the services defined in `docker-compose.yml`:
   ```bash
   docker-compose up
   ```

4. **Access the Application:**
   The application will be accessible at `http://localhost:8080`.

## Cloud Deployment

### Using Helm

To deploy Aegis in a Kubernetes environment using Helm, follow these steps:

1. **Install Helm:**
   Ensure that you have Helm installed on your local machine.

2. **Add the Aegis Helm Chart:**
   Navigate to the directory containing the Helm chart and install it:
   ```bash
   helm install aegis ./helm
   ```

3. **Configure Values:**
   You can customize the deployment by modifying the `values.yaml` file in the Helm chart directory. Key configurations include:
   - `replicaCount`: Number of replicas for the application.
   - `service.port`: Port for the service.
   - `ingress.enabled`: Enable ingress for external access.

4. **Run Migrations:**
   If migrations are required, ensure that the migration job is executed:
   ```bash
   kubectl apply -f helm/templates/migration-job.yaml
   ```

5. **Access the Application:**
   If ingress is enabled, access the application using the specified host.

### Using Terraform

To deploy Aegis using Terraform, follow these steps:

1. **Install Terraform:**
   Ensure that Terraform is installed on your local machine.

2. **Configure Terraform Variables:**
   Modify `terraform/variables.tf` to set up the necessary variables for your environment.

3. **Initialize Terraform:**
   Run the following command to initialize Terraform:
   ```bash
   terraform init
   ```

4. **Apply the Configuration:**
   Deploy the infrastructure by running:
   ```bash
   terraform apply
   ```

5. **Access the Application:**
   Similar to the Helm deployment, access the application using the configured endpoints.

## Environment Variables

Ensure that the following environment variables are set for both local and cloud deployments:

- `POSTGRES_DB`: Database name (default: `aegis`)
- `POSTGRES_USER`: Database user (default: `broker`)
- `POSTGRES_PASSWORD`: Database password (default: `changeme`)
- `ADMIN_PASSWORD`: Admin password (default: `changeme`)
- `SECRET_KEY`: Secret key for the application (default: `dev-secret-replace-in-prod`)

## Health Checks

Aegis includes health checks to monitor the application status. Ensure that the health endpoints are accessible:

- **Liveness Probe:** `/healthz`
- **Readiness Probe:** `/readyz`

These endpoints can be used to verify that the application is running correctly.
