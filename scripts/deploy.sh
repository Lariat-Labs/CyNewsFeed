#!/usr/bin/env bash
# Build the image in ACR (no local Docker needed) and deploy to Azure Container Apps.
# Usage: scripts/deploy.sh [image-tag]
set -euo pipefail
cd "$(dirname "$0")/../infra/terraform"

TAG="${1:-$(git describe --tags --always 2>/dev/null || date +%Y%m%d%H%M%S)}"
[ -f terraform.tfvars ] || { echo "Create infra/terraform/terraform.tfvars (see terraform.tfvars.example)"; exit 1; }

terraform init -input=false -upgrade >/dev/null

echo "==> Ensuring registry exists"
terraform apply -input=false -auto-approve \
  -target=azurerm_resource_group.rg -target=random_string.suffix -target=azurerm_container_registry.acr

ACR=$(terraform output -raw acr_name)
echo "==> Building image cynews:${TAG} in ${ACR}"
az acr build --registry "$ACR" --image "cynews:${TAG}" --image "cynews:latest" --build-arg VERSION="${TAG}" ../..

echo "==> Applying infrastructure with image tag ${TAG}"
terraform apply -input=false -var "image_tag=${TAG}"

echo
echo "App:        $(terraform output -raw app_url)"
echo "Run now:    az containerapp job start -g $(terraform output -raw resource_group) -n $(terraform output -raw aggregate_job)"
