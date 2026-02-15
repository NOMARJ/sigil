.PHONY: install test scan help lint api-dev api-test dashboard-dev cli-build docker-build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install sigil to /usr/local/bin
	chmod +x bin/sigil
	sudo cp bin/sigil /usr/local/bin/sigil
	@echo "Installed. Run: sigil install"

test: ## Run sigil self-scan
	./bin/sigil scan .

scan: ## Scan current directory
	./bin/sigil scan .

lint: ## Shellcheck the CLI script
	shellcheck bin/sigil

# ── API Service ──────────────────────────────────────────────────────────────

api-dev: ## Run FastAPI dev server with uvicorn (hot-reload)
	cd api && uvicorn main:app --reload --host 0.0.0.0 --port 8000

api-test: ## Run pytest on the API test suite
	cd api && python -m pytest -v --tb=short

# ── Dashboard ────────────────────────────────────────────────────────────────

dashboard-dev: ## Run Next.js dashboard in dev mode
	cd dashboard && npm run dev

# ── Rust CLI ─────────────────────────────────────────────────────────────────

cli-build: ## Build the Rust CLI binary (release mode)
	cd cli && cargo build --release
	@echo "Binary at: cli/target/release/sigil"

# ── Docker ───────────────────────────────────────────────────────────────────

docker-build: ## Build Docker images (placeholder)
	@echo "Docker build not yet configured."
	@echo "Planned images:"
	@echo "  sigil-api    — FastAPI service"
	@echo "  sigil-dash   — Next.js dashboard"
	@echo ""
	@echo "To build manually:"
	@echo "  docker build -t sigil-api -f api/Dockerfile api/"
	@echo "  docker build -t sigil-dash -f dashboard/Dockerfile dashboard/"
