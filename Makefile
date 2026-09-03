.PHONY: install test scan help lint api-dev api-test dashboard-dev cli-build docker-build docker-up docker-down docker-logs setup seed vscode-build vscode-dev mcp-build mcp-dev jetbrains-build plugins-build plugins-clean check-versions benchmark benchmark-quick

# ── Release / measurement configuration ─────────────────────────────────────
#
# The Datadog malicious-package dataset is NOT vendored (it is thousands of
# password-protected malware samples). Point these at your own checkout /
# control directory; see docs/benchmarks.md for how to obtain them.
SIGIL_EVAL_DATASET ?=
SIGIL_EVAL_CONTROL ?=
SIGIL_EVAL_OUT ?= evaluation_results

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: cli-build ## Build and install the Rust sigil CLI to /usr/local/bin
	# bin/ holds the legacy bash CLI (superseded by cli/) — no longer installed
	sudo cp cli/target/release/sigil /usr/local/bin/sigil
	@echo "Installed: /usr/local/bin/sigil"

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

# ── Plugins ─────────────────────────────────────────────────────────────────

vscode-build: ## Build VS Code extension (.vsix)
	cd plugins/vscode && npm install && npm run compile
	@echo "Build complete. Run 'cd plugins/vscode && npx vsce package' to create .vsix"

vscode-dev: ## Watch mode for VS Code extension development
	cd plugins/vscode && npm install && npm run watch

mcp-build: ## Build MCP server
	cd plugins/mcp-server && npm install && npm run build
	@echo "MCP server built. Run: node plugins/mcp-server/dist/index.js"

mcp-dev: ## Watch mode for MCP server development
	cd plugins/mcp-server && npm install && npm run dev

jetbrains-build: ## Build JetBrains plugin (.zip)
	cd plugins/jetbrains && gradle buildPlugin
	@echo "Plugin zip at: plugins/jetbrains/build/distributions/"

plugins-build: vscode-build mcp-build jetbrains-build ## Build all plugins

plugins-clean: ## Clean all plugin build artifacts
	rm -rf plugins/vscode/out plugins/vscode/node_modules plugins/vscode/*.vsix
	rm -rf plugins/mcp-server/dist plugins/mcp-server/node_modules
	rm -rf plugins/jetbrains/build plugins/jetbrains/.gradle

# ── Release ─────────────────────────────────────────────────────────────────

check-versions: ## Verify version alignment across every ship channel
	python3 scripts/check_versions.py

# ── Measurement ─────────────────────────────────────────────────────────────
#
# Both targets resolve the scanner the way scripts/run_eval.py does: $SIGIL_BIN,
# then cli/target/release/sigil, then PATH. Build first (`make cli-build`) or
# set SIGIL_BIN, or you will measure a stale binary.

define EVAL_VARS_MISSING
error: the benchmark needs a dataset and a clean control set, and neither is
vendored in this repository (the malicious dataset is thousands of
password-protected malware samples).

  make benchmark SIGIL_EVAL_DATASET=<dataset checkout> SIGIL_EVAL_CONTROL=<clean packages dir>

  SIGIL_EVAL_DATASET  checkout of DataDog/malicious-software-packages-dataset
  SIGIL_EVAL_CONTROL  directory whose immediate subdirs are extracted clean packages
  SIGIL_EVAL_OUT      output directory (default: evaluation_results)

Use `benchmark-quick` (--limit 30) while iterating; `benchmark` for a number
anyone is going to publish. See docs/benchmarks.md for the method and
docs/RELEASING.md for when in the release this runs.
endef
export EVAL_VARS_MISSING

benchmark: ## Full detection benchmark (needs SIGIL_EVAL_DATASET + SIGIL_EVAL_CONTROL)
	@if [ -z "$(SIGIL_EVAL_DATASET)" ] || [ -z "$(SIGIL_EVAL_CONTROL)" ]; then \
		echo "$$EVAL_VARS_MISSING" >&2; \
		exit 1; \
	fi
	python3 scripts/run_eval.py \
		--dataset datadog \
		--dataset-path "$(SIGIL_EVAL_DATASET)" \
		--control-path "$(SIGIL_EVAL_CONTROL)" \
		--out "$(SIGIL_EVAL_OUT)"

benchmark-quick: ## Same benchmark capped at 30 samples per bucket (iteration only)
	@if [ -z "$(SIGIL_EVAL_DATASET)" ] || [ -z "$(SIGIL_EVAL_CONTROL)" ]; then \
		echo "$$EVAL_VARS_MISSING" >&2; \
		exit 1; \
	fi
	@echo "NOTE: this overwrites $(SIGIL_EVAL_OUT)/honest_detection_eval.{json,md} with a"
	@echo "      30-per-bucket run. Never commit its output as the published measurement —"
	@echo "      set SIGIL_EVAL_OUT to a scratch directory if that matters."
	python3 scripts/run_eval.py \
		--dataset datadog \
		--dataset-path "$(SIGIL_EVAL_DATASET)" \
		--control-path "$(SIGIL_EVAL_CONTROL)" \
		--out "$(SIGIL_EVAL_OUT)" \
		--limit 30

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
