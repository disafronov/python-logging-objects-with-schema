# Variables
PYTEST_CMD = uv run python -m pytest -v
COVERAGE_OPTS = --cov --cov-report=term-missing --cov-report=html

# Phony targets
.PHONY: all clean dead-code format help install lint test test-coverage

# Default target
help: ## Show this help message
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

################################################################################

# Development
install: ## Install dependencies
	@echo "Installing dependencies..."
	uv sync
	@echo "Installing pre-commit hooks..."
	uv run pre-commit install

# Code quality
format: ## Format code
	@echo "Formatting code..."
	uv run black . && uv run isort .

lint: ## Run linting tools
	@echo "Running linting tools..."
	uv run black --check . && uv run isort --check-only . && uv run flake8 . && uv run mypy . && uv run bandit -r -c pyproject.toml .

dead-code: ## Check for dead code using vulture
	@echo "Checking for dead code..."
	uv run vulture

# Testing
test: ## Run tests
	@echo "Running tests..."
	$(PYTEST_CMD)

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(PYTEST_CMD) $(COVERAGE_OPTS)

# Combined operations
all: format lint test dead-code ## Run format, lint, test, and dead-code check
	@echo "All checks completed successfully!"

# Maintenance
clean: ## Clean cache and temporary files
	@echo "Cleaning cache and temporary files..."
	rm -rf .mypy_cache/ .pytest_cache/ .venv/ build/ dist/ htmlcov/ .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
