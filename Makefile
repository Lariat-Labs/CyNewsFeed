SHELL := /bin/bash
.DEFAULT_GOAL := help
AZURITE_CONN := DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;TableEndpoint=http://127.0.0.1:10002/devstoreaccount1;

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

install: ## Install frontend deps and Go modules
	cd frontend && npm ci
	cd backend && go mod download

web: ## Build the SPA into the Go embed dir
	cd frontend && npm run build

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build: web ## Build the single binary to ./bin/cynews
	cd backend && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o ../bin/cynews ./cmd/cynews

azurite: ## Start Azurite (storage emulator) in Docker
	@docker start cynews-azurite >/dev/null 2>&1 || docker run -d --name cynews-azurite -p 10000:10000 -p 10002:10002 \
	  mcr.microsoft.com/azure-storage/azurite azurite --blobHost 0.0.0.0 --tableHost 0.0.0.0 --skipApiVersionCheck --loose >/dev/null
	@echo "Azurite running on :10000 (blob) / :10002 (table)"

dev-api: azurite ## Run the Go API against Azurite (reads .env)
	cd backend && set -f && set -a && [ -f ../.env ] && . ../.env; set +a; set +f; \
	  STORAGE_MODE=azure AZURE_STORAGE_CONNECTION_STRING='$(AZURITE_CONN)' go run ./cmd/cynews serve

dev-web: ## Run the Vite dev server (proxies /api to :8080)
	cd frontend && npm run dev

run-once: azurite ## One aggregation pass against Azurite
	cd backend && set -f && set -a && [ -f ../.env ] && . ../.env; set +a; set +f; \
	  STORAGE_MODE=azure AZURE_STORAGE_CONNECTION_STRING='$(AZURITE_CONN)' go run ./cmd/cynews run

test: ## Unit + pipeline tests
	cd backend && go vet ./... && go test ./...
	cd frontend && npx tsc -b

test-azurite: azurite ## Include the Azure Table/Blob store integration test
	cd backend && AZURITE=1 go test -count=1 ./...

up: ## docker compose up (app + Azurite)
	docker compose up --build

tf-init: ## terraform init
	cd infra/terraform && terraform init

tf-plan: ## terraform plan
	cd infra/terraform && terraform plan

deploy: ## Build image in ACR and deploy to Azure Container Apps
	./scripts/deploy.sh

.PHONY: help install web build azurite dev-api dev-web run-once test test-azurite up tf-init tf-plan deploy
