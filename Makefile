.PHONY: help install install-dev test lint demo audit serve docker-build docker-run clean

PY ?= python3
REPORT_HTML ?= report.html
REPORT_MD ?= report.md

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime (web UI) deps
	$(PY) -m pip install -r requirements.txt

install-dev: ## Install dev + test deps
	$(PY) -m pip install -r requirements-dev.txt

test: ## Run the test suite (offline)
	$(PY) -m pytest -q

lint: ## Lint with ruff (if installed)
	@$(PY) -m ruff check . || echo "ruff not installed; skipping"

demo: ## Audit the sample contracts and open the HTML report
	$(PY) -m auditor.cli samples --html $(REPORT_HTML) --md $(REPORT_MD) --open
	@echo "Report written to $(REPORT_HTML) and $(REPORT_MD)"

audit: ## Audit a path: make audit PATH=path/to/contracts
	$(PY) -m auditor.cli $(PATH) --html $(REPORT_HTML) --md $(REPORT_MD)

serve: ## Run the FastAPI web UI on :8000
	$(PY) -m uvicorn auditor.webapp:app --host 0.0.0.0 --port 8000

docker-build: ## Build the container image
	docker build -t solidity-audit-ai .

docker-run: ## Run the web UI container on :8000
	docker run --rm -p 8000:8000 solidity-audit-ai

clean: ## Remove caches and generated reports
	rm -rf .pytest_cache .ruff_cache **/__pycache__ __pycache__ *.egg-info
	rm -f $(REPORT_HTML) $(REPORT_MD)
