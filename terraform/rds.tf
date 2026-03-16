resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db-subnet"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_rds_cluster" "main" {
  cluster_identifier      = "${local.name}-postgres"
  engine                  = "aurora-postgresql"
  engine_version          = "16.1"
  database_name           = "aegis"
  master_username         = "broker"
  master_password         = random_password.db.result
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.rds.id]
  storage_encrypted       = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "${local.name}-final-snapshot"
  deletion_protection     = true

  tags = { Name = "${local.name}-aurora" }
}

resource "aws_rds_cluster_instance" "main" {
  count                = 2
  identifier           = "${local.name}-postgres-${count.index}"
  cluster_identifier   = aws_rds_cluster.main.id
  instance_class       = var.db_instance_class
  engine               = aws_rds_cluster.main.engine
  engine_version       = aws_rds_cluster.main.engine_version
  db_subnet_group_name = aws_db_subnet_group.main.name

  tags = { Name = "${local.name}-aurora-instance-${count.index}" }
}
