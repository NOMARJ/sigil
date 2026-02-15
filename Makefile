.PHONY: install test scan help

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
