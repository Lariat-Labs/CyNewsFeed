# Deployment (Azure)

CyNewsFeed deploys to **Azure Container Apps** with Terraform (`infra/terraform`).

## What gets created

| Resource | Purpose |
|---|---|
| Container App `ca-<name>` | API + UI, scales 0→1, Entra ID sign-in (Easy Auth) |
| Container Apps Jobs `caj-<name>-aggregate` / `-digest` | Hourly aggregation and daily digest (cron in **UTC**) |
| Storage account | Tables (feeds, items, rules, alerts, runs, digests, chats, usage, reports, settings) + Blob (article text, chats, locks). Shared keys disabled |
| User-assigned managed identity | Table/Blob Data Contributor, AcrPull, Key Vault Secrets User |
| Key Vault | AI keys, Slack webhook, intel API keys, generated TAXII/MCP tokens |
| Azure Container Registry | Images (built in the cloud with `az acr build`) |
| Log Analytics | Container logs |
| Entra app registration (optional) | Easy Auth sign-in for your tenant |

## Deploy

```bash
az login
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars   # fill in
make deploy          # scripts/deploy.sh
```

`scripts/deploy.sh` creates the registry, builds the image in ACR (no local Docker needed), then applies Terraform with
that image tag. Re-run it to ship new versions.

### Key `terraform.tfvars` settings

```hcl
subscription_id   = "…"
location          = "eastus2"
ai_provider       = "claude"
anthropic_api_key = "sk-ant-…"
claude_model      = "claude-haiku-5-5"   # per-story summaries (on demand by default)
slack_webhook_url = "https://hooks.slack.com/services/…"
digest_cron_utc   = "0 14 * * *"         # 08:00 US Central
enable_auth       = true                 # Entra ID sign-in
# optional: virustotal_api_key, abuseipdb_api_key, nvd_api_key, misp_url, misp_key
```

!!! danger "Terraform state contains secrets"
    The local `terraform.tfstate` stores secret values in plain text and is git-ignored. For team use, enable the
    `azurerm` remote backend block in `infra/terraform/versions.tf`.

## After deploying

```bash
cd infra/terraform
terraform output app_url
terraform output -raw taxii_token     # TAXII password
terraform output -raw mcp_token       # MCP bearer token
az containerapp job start -g rg-cynews -n caj-cynews-aggregate   # run an aggregation now
```

- The app requires Entra sign-in. `/healthz`, `/mcp` and `/taxii2/*` are excluded from Easy Auth and use their own tokens.
- The app scales to zero, so the first request after idle can take about a minute. Set `min_replicas = 1` in `main.tf` to
  avoid that, for roughly $10–15/month.

## Without Entra sign-in

Set `enable_auth = false` if you can't create app registrations. The app is then **public**, so put it behind another
access control such as IP restrictions, Front Door with WAF, or a private environment.
