.PHONY: help build test check clean format lint

help: ## Show this help message
	@echo "Available commands:"
	@echo "  build     - Build the project"
	@echo "  test      - Run all tests"
	@echo "  test-simple - Run simple compilation test"
	@echo "  test-integration - Run comprehensive security tests"
	@echo "  setup-env - Set up environment variables"
	@echo "  check     - Check for compilation errors"
	@echo "  clean     - Clean build artifacts"
	@echo "  format    - Format code"
	@echo "  lint      - Run clippy linting"

build: ## Build the project
	@echo "🔨 Building voting system..."
	@cargo build
	@echo "✅ Build complete"

test: ## Run all tests
	@echo "🧪 Running tests..."
	@cargo test
	@echo "✅ Tests complete"

check: ## Check for compilation errors
	@echo "🔍 Checking code..."
	@cargo check
	@echo "✅ Check complete"

clean: ## Clean build artifacts
	@echo "🧹 Cleaning..."
	@cargo clean
	@echo "✅ Clean complete"

format: ## Format code
	@echo " Formatting code..."
	@cargo fmt
	@echo "✅ Format complete"

audit: ## Audit code
	@echo "🔍 Auditing code..."
	@cargo audit
	@echo "✅ Audit complete"

lint: ## Run clippy linting
	@echo "🔍 Running clippy..."
	@cargo clippy --all-targets --all-features -- -D warnings
	@echo "✅ Lint complete"

# Integration test specifically
test-integration: ## Run integration tests with output
	@echo "🧪 Running integration tests..."
	@cargo test --test integration_test -- --nocapture
	@echo "✅ Integration tests complete"

# Simple test specifically
test-simple: ## Run simple tests with output
	@echo "🧪 Running simple tests..."
	@cargo test --test simple_test -- --nocapture
	@echo "✅ Simple tests complete"

# Quick development cycle
dev: check test-simple ## Quick development check (compile + simple test)
	@echo "✅ Development cycle complete"

# Get ready before commit
ready: check test lint format audit ## Full development check (check + test + lint + format + audit)
	@echo "✅ Ready to commit"