variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "app_name" {
  description = "Application name — used as a prefix for all resource names"
  type        = string
  default     = "aegis"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "db_instance_class" {
  description = "RDS Aurora instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "fargate_cpu" {
  description = "ECS task CPU units (256, 512, 1024, 2048, 4096)"
  type        = number
  default     = 512
}

variable "fargate_memory" {
  description = "ECS task memory in MiB"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of ECS task instances"
  type        = number
  default     = 2
}

variable "image_uri" {
  description = "Full ECR image URI including tag, e.g. 123456789.dkr.ecr.us-east-1.amazonaws.com/aegis:latest"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the ACM TLS certificate, e.g. aegis.example.com"
  type        = string
}

variable "admin_password" {
  description = "Admin panel password"
  type        = string
  sensitive   = true
}

variable "secret_key" {
  description = "Session signing secret (min 32 chars — generate with: openssl rand -hex 32)"
  type        = string
  sensitive   = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "rate_limit_rpm" {
  description = "Default requests-per-minute rate limit per API key"
  type        = number
  default     = 60
}
