.DEFAULT_GOAL := help
SHELL         := /bin/bash
IMAGE         ?= aegis
TAG           ?= latest
REGISTRY      ?= ""

# ─────────────────────────────────────────────────────────────────────────────
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ── Dev ───────────────────────────────────────────────────────────────────────
.PHONY: dev
dev: ## Start dev environment (build + up)
	docker compose up --build

.PHONY: dev-d
dev-d: ## Start dev environment in background
	docker compose up --build -d

.PHONY: dev-down
dev-down: ## Stop dev environment
	docker compose down

.PHONY: dev-logs
dev-logs: ## Follow broker logs
	docker compose logs -f broker

.PHONY: dev-reset
dev-reset: ## Stop dev and wipe all volumes (destructive)
	docker compose down -v

# ── Production ────────────────────────────────────────────────────────────────
.PHONY: prod
prod: ## Start production environment
	docker compose -f docker-compose.prod.yml up -d

.PHONY: prod-down
prod-down: ## Stop production environment
	docker compose -f docker-compose.prod.yml down

.PHONY: prod-logs
prod-logs: ## Follow production broker logs
	docker compose -f docker-compose.prod.yml logs -f broker

.PHONY: prod-ps
prod-ps: ## Show production container status
	docker compose -f docker-compose.prod.yml ps

# ── Build & Push ──────────────────────────────────────────────────────────────
.PHONY: build
build: ## Build Docker image
	docker build -t $(IMAGE):$(TAG) .

.PHONY: push
push: ## Push image to registry (set REGISTRY=your-registry.com/repo)
	@[ -n "$(REGISTRY)" ] || (echo "ERROR: REGISTRY is not set" && exit 1)
	docker tag $(IMAGE):$(TAG) $(REGISTRY):$(TAG)
	docker push $(REGISTRY):$(TAG)

# ── Database ──────────────────────────────────────────────────────────────────
.PHONY: migrate
migrate: ## Run Alembic migrations (alembic upgrade head)
	docker compose exec broker alembic upgrade head

.PHONY: migrate-new
migrate-new: ## Create a new migration (usage: make migrate-new name=add_foo)
	@[ -n "$(name)" ] || (echo "Usage: make migrate-new name=<description>" && exit 1)
	docker compose exec broker alembic revision --autogenerate -m "$(name)"

.PHONY: migrate-history
migrate-history: ## Show migration history
	docker compose exec broker alembic history --verbose

.PHONY: migrate-current
migrate-current: ## Show current migration revision
	docker compose exec broker alembic current

.PHONY: psql
psql: ## Open psql shell against dev Postgres
	docker compose exec postgres psql -U $${POSTGRES_USER:-broker} -d $${POSTGRES_DB:-aegis}

# ── Redis ─────────────────────────────────────────────────────────────────────
.PHONY: redis-cli
redis-cli: ## Open redis-cli against dev Redis
	docker compose exec redis redis-cli

# ── Backup ────────────────────────────────────────────────────────────────────
.PHONY: backup
backup: ## Dump dev Postgres to ./backups/
	@mkdir -p backups
	@STAMP=$$(date +%Y%m%d_%H%M%S); \
	docker compose exec -T postgres pg_dump \
	  -U $${POSTGRES_USER:-broker} $${POSTGRES_DB:-aegis} \
	  | gzip > backups/aegis_$${STAMP}.sql.gz && \
	echo "Backup written to backups/aegis_$${STAMP}.sql.gz"

.PHONY: restore
restore: ## Restore from a dump file (usage: make restore file=backups/aegis_xxx.sql.gz)
	@[ -n "$(file)" ] || (echo "Usage: make restore file=<path>" && exit 1)
	gunzip -c $(file) | docker compose exec -T postgres psql \
	  -U $${POSTGRES_USER:-broker} -d $${POSTGRES_DB:-aegis}

# ── Shell ─────────────────────────────────────────────────────────────────────
.PHONY: shell
shell: ## Open a shell in the broker container
	docker compose exec broker sh

# ── Tests ─────────────────────────────────────────────────────────────────────
.PHONY: test-db
test-db: ## Create aegis_test database in dev Postgres (run once before make test)
	docker compose exec -T postgres createdb -U $${POSTGRES_USER:-broker} aegis_test 2>/dev/null || true

.PHONY: test
test: ## Run tests locally (dev stack must be running: make dev-d; run make test-db first)
	DATABASE_URL=postgresql://$${POSTGRES_USER:-broker}:$${POSTGRES_PASSWORD:-changeme}@localhost:5432/aegis_test \
	  pytest tests/ -v --tb=short

.PHONY: test-cov
test-cov: ## Run tests with coverage report
	DATABASE_URL=postgresql://$${POSTGRES_USER:-broker}:$${POSTGRES_PASSWORD:-changeme}@localhost:5432/aegis_test \
	  pytest tests/ -v --tb=short --cov=. --cov-report=term-missing

.PHONY: lint
lint: ## Run ruff linter on tests/
	ruff check tests/

# ── Helm ──────────────────────────────────────────────────────────────────────
.PHONY: helm-deps
helm-deps: ## Update Helm chart dependencies
	helm dependency update helm/

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	helm lint helm/

.PHONY: helm-template
helm-template: ## Render Helm templates (dry run)
	helm template aegis helm/ --values helm/values.yaml

.PHONY: helm-install
helm-install: ## Install Helm chart (set NAMESPACE and --set overrides as needed)
	helm upgrade --install aegis helm/ \
	  --namespace $${NAMESPACE:-aegis} \
	  --create-namespace \
	  --values helm/values.yaml

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall Helm release
	helm uninstall aegis --namespace $${NAMESPACE:-aegis}

# ── Terraform ─────────────────────────────────────────────────────────────────
.PHONY: tf-init
tf-init: ## Initialise Terraform
	cd terraform && terraform init

.PHONY: tf-plan
tf-plan: ## Terraform plan
	cd terraform && terraform plan

.PHONY: tf-apply
tf-apply: ## Terraform apply
	cd terraform && terraform apply

.PHONY: tf-destroy
tf-destroy: ## Terraform destroy (destructive — prompts for confirmation)
	cd terraform && terraform destroy

.PHONY: tf-fmt
tf-fmt: ## Format Terraform files
	cd terraform && terraform fmt -recursive

.PHONY: tf-validate
tf-validate: ## Validate Terraform configuration
	cd terraform && terraform validate

# ── Misc ──────────────────────────────────────────────────────────────────────
.PHONY: env
env: ## Copy .env.example to .env if .env does not exist
	@[ -f .env ] && echo ".env already exists" || (cp .env.example .env && echo "Created .env from .env.example — fill in your values")

.PHONY: health
health: ## Check broker health endpoint
	@curl -sf http://localhost:8080/health | python3 -m json.tool || echo "Broker not responding"
