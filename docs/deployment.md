# Deployment

## Local Deployment

To deploy Aegis locally, you can use Docker Compose. Follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/gustav0thethird/Aegis.git
   cd Aegis
   ```

2. **Create a `.env` File**:
   Copy the `.env.example` to `.env` and modify the environment variables as needed.

3. **Start Services**:
   Use Docker Compose to start the services:
   ```bash
   docker-compose up
   ```

   This will start the following services:
   - PostgreSQL
   - Redis
   - Aegis Broker

4. **Access the Application**:
   The Aegis application will be available at `http://localhost:8080`.

## Cloud Deployment

For cloud deployment, you can use Helm to deploy Aegis on a Kubernetes cluster. Follow these steps:

1. **Install Helm**:
   Ensure you have Helm installed on your machine.

2. **Add the Aegis Helm Chart**:
   Navigate to the Helm directory:
   ```bash
   cd helm
   ```

3. **Configure Values**:
   Modify the `values.yaml` file to set your desired configurations, such as database credentials and resource limits.

4. **Deploy Aegis**:
   Use the following command to deploy Aegis:
   ```bash
   helm install aegis .
   ```

5. **Verify Deployment**:
   Check the status of the deployment:
   ```bash
   kubectl get pods
   ```

6. **Access the Application**:
   If you have set up an Ingress, access the application using the configured host. Otherwise, you can port-forward to access it:
   ```bash
   kubectl port-forward svc/aegis 8080:8080
   ```

## Migration

If you need to run database migrations, you can do so using the following command:
```bash
kubectl create job --from=cronjob/aegis-migrate aegis-migrate-job
```

This job will apply any pending migrations to the database.

## Environment Variables

Ensure the following environment variables are set in your deployment configuration:

- `DATABASE_URL`: Connection string for PostgreSQL.
- `REDIS_URL`: Connection string for Redis.
- `ADMIN_PASSWORD`: Password for the admin user.
- `SECRET_KEY`: Secret key for the application.

## Health Checks

Aegis includes health checks for both liveness and readiness. Ensure these endpoints are accessible:

- Liveness: `/healthz`
- Readiness: `/readyz`

These checks will help ensure that your application is running correctly and is ready to serve traffic.
