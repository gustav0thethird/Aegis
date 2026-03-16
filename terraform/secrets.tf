locals {
  db_url    = "postgresql://broker:${random_password.db.result}@${aws_rds_cluster.main.endpoint}:5432/aegis"
  redis_url = "rediss://:${random_password.redis_auth.result}@${aws_elasticache_replication_group.main.primary_endpoint_address}:6379"
}

# ── DATABASE_URL ──────────────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "database_url" {
  name                    = "${var.app_name}/${var.environment}/database-url"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = local.db_url
}

# ── REDIS_URL ─────────────────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "redis_url" {
  name                    = "${var.app_name}/${var.environment}/redis-url"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id     = aws_secretsmanager_secret.redis_url.id
  secret_string = local.redis_url
}

# ── ADMIN_PASSWORD ────────────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "admin_password" {
  name                    = "${var.app_name}/${var.environment}/admin-password"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "admin_password" {
  secret_id     = aws_secretsmanager_secret.admin_password.id
  secret_string = var.admin_password
}

# ── SECRET_KEY ────────────────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "secret_key" {
  name                    = "${var.app_name}/${var.environment}/secret-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "secret_key" {
  secret_id     = aws_secretsmanager_secret.secret_key.id
  secret_string = var.secret_key
}
