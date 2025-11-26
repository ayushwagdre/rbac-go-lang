.PHONY: help setup db-start db-stop db-restart db-logs db-shell run dev clean

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Initial setup (create .env and start database)
	@echo "🔧 Setting up the project..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Created .env file from .env.example"; \
	else \
		echo "ℹ️  .env file already exists"; \
	fi
	@make db-start
	@echo ""
	@echo "✅ Setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit .env if needed (especially JWT_SECRET)"
	@echo "  2. Run 'make run' to start the application"

db-start: ## Start PostgreSQL database
	@echo "🐘 Starting PostgreSQL..."
	@docker-compose up -d
	@echo "⏳ Waiting for database to be ready..."
	@sleep 3
	@echo "✅ PostgreSQL is running on localhost:5432"

db-stop: ## Stop PostgreSQL database
	@echo "🛑 Stopping PostgreSQL..."
	@docker-compose down
	@echo "✅ PostgreSQL stopped"

db-restart: ## Restart PostgreSQL database
	@make db-stop
	@make db-start

db-logs: ## View PostgreSQL logs
	@docker-compose logs -f postgres

db-shell: ## Connect to PostgreSQL shell
	@docker exec -it rolebasedgo-postgres psql -U rolebasedgo -d rolebasedgo

run: ## Run the application
	@if [ ! -f .env ]; then \
		echo "❌ .env file not found. Run 'make setup' first."; \
		exit 1; \
	fi
	@echo "🚀 Starting the application..."
	@export $$(cat .env | xargs) && go run main.go

dev: ## Run in development mode with auto-reload (requires air)
	@if ! command -v air > /dev/null; then \
		echo "📦 Installing air for hot reload..."; \
		go install github.com/cosmtrek/air@latest; \
	fi
	@export $$(cat .env | xargs) && air

build: ## Build the application
	@echo "🔨 Building..."
	@go build -o bin/server main.go
	@echo "✅ Built to bin/server"

clean: ## Clean up database and volumes
	@echo "🧹 Cleaning up..."
	@docker-compose down -v
	@rm -rf bin/
	@echo "✅ Cleanup complete"

test: ## Run tests
	@go test -v ./...

deps: ## Download dependencies
	@go mod download
	@go mod tidy
