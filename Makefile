# Python version is pinned via `.python-version` (used by uv and CI).
PYTHON_VERSION := $(shell tr -d '[:space:]' < .python-version)

# Variables
UV = uv
UV_RUN = $(UV) run --locked
PYTEST_CMD = $(UV_RUN) python -m pytest -v
COVERAGE_OPTS = --cov --cov-report=term-missing --cov-report=html

# Phony targets
.PHONY: all audit clean dead-code format help install lint test

# Default target
help: ## Show this help message
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

################################################################################

# Development
install: ## Install dependencies
	@echo "Installing dependencies..."
	$(UV) python install $(PYTHON_VERSION)
	$(UV) sync --locked --python $(PYTHON_VERSION)
	@echo "Installing pre-commit hooks..."
	$(UV_RUN) pre-commit install

# Code quality
format: ## Format code
	@echo "Formatting code..."
	$(UV_RUN) black . && $(UV_RUN) isort .

lint: ## Run linting tools
	@echo "Running linting tools..."
	$(UV_RUN) black --check . && $(UV_RUN) isort --check-only . && $(UV_RUN) flake8 . && $(UV_RUN) mypy && $(UV_RUN) bandit -c pyproject.toml -r src/

dead-code: ## Check for dead code using vulture
	@echo "Checking for dead code..."
	$(UV_RUN) vulture

audit: ## Check dependencies for known vulnerabilities
	@echo "Auditing dependencies..."
	$(UV_RUN) --with pip-audit pip-audit

# Testing
test: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(PYTEST_CMD) $(COVERAGE_OPTS)

# Combined operations
all: lint test dead-code ## Run lint, test, and dead-code check
	@echo "All checks completed successfully!"

# Maintenance
clean: ## Clean cache and temporary files
	@echo "Cleaning cache and temporary files..."
	rm -rf .mypy_cache/ .pytest_cache/ .venv/ build/ dist/ htmlcov/ .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
