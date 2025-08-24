.PHONY: help install install-dev test lint format clean certs run-server run-client demo

# Default target
help:
	@echo "Hyperloop Secure Communication - Development Commands"
	@echo ""
	@echo "Installation:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  test         Run tests with pytest"
	@echo "  lint         Run linting with flake8"
	@echo "  format       Format code with black"
	@echo "  type-check   Run type checking with mypy"
	@echo ""
	@echo "Certificates:"
	@echo "  certs        Generate test certificates"
	@echo ""
	@echo "Running:"
	@echo "  run-server   Start the server"
	@echo "  run-client   Start the client"
	@echo "  demo         Run the complete demo"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean        Clean up generated files"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -e ".[dev]"

# Development tasks
test:
	python -m pytest tests/ -v --cov=. --cov-report=term-missing

lint:
	flake8 . --max-line-length=88 --extend-ignore=E203,W503

format:
	black . --line-length=88

type-check:
	mypy . --ignore-missing-imports

# Certificate generation
certs:
	cd certs && python make_test_certs.py

# Running the application
run-server: certs
	python server.py

run-client: certs
	python client.py

demo: certs
	@echo "Starting Hyperloop demo..."
	@echo "1. Starting server in background..."
	@python server.py &
	@sleep 2
	@echo "2. Starting client..."
	@python client.py

# Cleanup
clean:
	rm -rf certs/out/
	rm -f certs/*.ext
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
