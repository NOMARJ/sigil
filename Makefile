.PHONY: install test scan help lint api-dev api-test dashboard-dev cli-build docker-build docker-up docker-down docker-logs setup seed

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

docker-build: ## Build Docker images
	docker compose build

docker-up: ## Start all services in the background
	docker compose up -d

docker-down: ## Stop all services
	docker compose down

docker-logs: ## Tail logs from all services
	docker compose logs -f

# ── Setup & Seed ─────────────────────────────────────────────────────────────

setup: ## Full local dev setup (install deps for api + dashboard)
	@echo "==> Installing API dependencies..."
	cd api && pip install -r requirements.txt
	@echo ""
	@echo "==> Installing dashboard dependencies..."
	cd dashboard && npm install
	@echo ""
	@echo "==> Initializing sigil directories..."
	chmod +x bin/sigil
	./bin/sigil config --init
	@echo ""
	@echo "Setup complete. Run 'make api-dev' and 'make dashboard-dev' to start."

seed: ## Run seed data script
	@if [ -f api/seed.py ]; then \
		echo "==> Running API seed script..."; \
		cd api && python seed.py; \
	elif [ -f scripts/seed.py ]; then \
		echo "==> Running seed script..."; \
		python scripts/seed.py; \
	elif [ -f seed.py ]; then \
		echo "==> Running seed script..."; \
		python seed.py; \
	else \
		echo "No seed script found. Expected one of:"; \
		echo "  api/seed.py"; \
		echo "  scripts/seed.py"; \
		echo "  seed.py"; \
	fi
