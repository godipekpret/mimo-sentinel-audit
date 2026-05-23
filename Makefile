.PHONY: install test lint format clean docker-build docker-run audit help

PYTHON := python3
PIP := pip3
DOCKER := docker

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -e ".[dev]"

test: ## Run test suite
	$(PYTHON) -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage
	$(PYTHON) -m pytest tests/ -v --cov=src --cov-report=html

lint: ## Run linter
	ruff check src/ tests/
	mypy src/

format: ## Format code
	ruff format src/ tests/

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

docker-build: ## Build Docker image
	$(DOCKER) build -t mimo-sentinel-audit .

docker-run: ## Run Docker container
	$(DOCKER) run --rm -it --env-file .env mimo-sentinel-audit

docker-compose-up: ## Start all services
	docker-compose up -d

docker-compose-down: ## Stop all services
	docker-compose down

audit: ## Run audit on example contract
	$(PYTHON) -m sentinel audit examples/vulnerable_token.sol --output reports/audit_report.html

monitor: ## Start mempool monitoring
	$(PYTHON) -m sentinel monitor --chain ethereum --duration 3600

setup-dev: install ## Setup development environment
	$(PIP) install -e ".[dev,full]"
	pre-commit install 2>/dev/null || true

all: clean install test lint ## Run full CI pipeline
