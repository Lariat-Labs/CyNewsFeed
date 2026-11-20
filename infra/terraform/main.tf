data "azurerm_client_config" "current" {}

# Machine-to-machine tokens for the TAXII feed and the MCP server.
resource "random_password" "taxii" {
  length  = 40
  special = false
}

resource "random_password" "mcp" {
  length  = 40
  special = false
}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

locals {
  suffix   = random_string.suffix.result
  app_name = "ca-${var.name}"
  # Container Apps FQDN is deterministic: <app>.<environment default domain>.
  # Computing it avoids a dependency cycle between the app, its env vars and auth.
  app_fqdn = "${local.app_name}.${azurerm_container_app_environment.env.default_domain}"
  app_url  = "https://${local.app_fqdn}"
  image    = "${azurerm_container_registry.acr.login_server}/cynews:${var.image_tag}"

  optional_secrets = {
    "anthropic-api-key" = { value = var.anthropic_api_key, env = "ANTHROPIC_API_KEY" }
    "azure-openai-key"  = { value = var.azure_openai_api_key, env = "AZURE_OPENAI_API_KEY" }
    "slack-webhook-url" = { value = var.slack_webhook_url, env = "SLACK_WEBHOOK_URL" }
    "virustotal-key"    = { value = var.virustotal_api_key, env = "VIRUSTOTAL_API_KEY" }
    "abuseipdb-key"     = { value = var.abuseipdb_api_key, env = "ABUSEIPDB_API_KEY" }
    "nvd-key"           = { value = var.nvd_api_key, env = "NVD_API_KEY" }
    "misp-key"          = { value = var.misp_key, env = "MISP_KEY" }
  }
  # Generated tokens: always present, values known only after apply.
  token_secrets = {
    "taxii-token" = { value = random_password.taxii.result, env = "TAXII_TOKEN" }
    "mcp-token"   = { value = random_password.mcp.result, env = "MCP_TOKEN" }
  }
  secrets = merge(local.optional_secrets, local.token_secrets)
  # Key names are not sensitive; only create optional secrets that were provided.
  secret_names = toset(concat(keys(local.token_secrets), [for k, v in local.optional_secrets : k if nonsensitive(v.value != "")]))

  env = {
    STORAGE_MODE            = "azure"
    AZURE_STORAGE_ACCOUNT   = azurerm_storage_account.st.name
    AZURE_CLIENT_ID         = azurerm_user_assigned_identity.app.client_id
    AI_PROVIDER             = var.ai_provider
    CLAUDE_MODEL            = var.claude_model
    CLAUDE_DIGEST_MODEL     = var.claude_digest_model
    CLAUDE_CHAT_MODEL       = var.claude_chat_model
    AZURE_OPENAI_ENDPOINT   = var.azure_openai_endpoint
    AZURE_OPENAI_DEPLOYMENT = var.azure_openai_deployment
    PUBLIC_BASE_URL         = local.app_url
    TZ                      = var.timezone
    RETENTION_DAYS          = tostring(var.retention_days)
    LOG_FORMAT              = "json"
    SCHEDULER_ENABLED       = "false" # scheduling is done by Container Apps Jobs
    AUTH_MODE               = var.enable_auth ? "easyauth" : "none"
    MISP_URL                = var.misp_url
  }
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-${var.name}"
  location = var.location
  tags     = var.tags
}

resource "azurerm_log_analytics_workspace" "law" {
  name                = "log-${var.name}-${local.suffix}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

# ---------------- Storage (state: Tables + Blob) ----------------

resource "azurerm_storage_account" "st" {
  name                            = "st${var.name}${local.suffix}"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Entra ID (managed identity) only
  tags                            = var.tags

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }
}
# Tables and the blob container are created by the app on startup (idempotent).

# ---------------- Identity & RBAC ----------------

resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${var.name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "table" {
  scope                = azurerm_storage_account.st.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "blob" {
  scope                = azurerm_storage_account.st.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  principal_type       = "ServicePrincipal"
}

# Lets the deploying user inspect data (Storage Explorer / az storage entity query).
resource "azurerm_role_assignment" "table_deployer" {
  scope                = azurerm_storage_account.st.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ---------------- Container registry ----------------

resource "azurerm_container_registry" "acr" {
  name                = "acr${var.name}${local.suffix}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = var.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  principal_type       = "ServicePrincipal"
}

# ---------------- Key Vault (secrets) ----------------

resource "azurerm_key_vault" "kv" {
  name                       = "kv-${var.name}-${local.suffix}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = azurerm_resource_group.rg.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  tags                       = var.tags
}

resource "azurerm_role_assignment" "kv_deployer" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "kv_app" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_key_vault_secret" "s" {
  for_each     = local.secret_names
  name         = each.key
  value        = local.secrets[each.key].value
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_role_assignment.kv_deployer]
}

# ---------------- Container Apps ----------------

resource "azurerm_container_app_environment" "env" {
  name                       = "cae-${var.name}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = azurerm_resource_group.rg.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  tags                       = var.tags
}

resource "azurerm_container_app" "app" {
  name                         = local.app_name
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = azurerm_user_assigned_identity.app.id
  }

  dynamic "secret" {
    for_each = local.secret_names
    content {
      name                = secret.key
      key_vault_secret_id = azurerm_key_vault_secret.s[secret.key].versionless_id
      identity            = azurerm_user_assigned_identity.app.id
    }
  }

  dynamic "secret" {
    for_each = var.enable_auth ? [1] : []
    content {
      name  = "microsoft-provider-authentication-secret"
      value = azuread_application_password.auth[0].value
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 0
    max_replicas = 1

    container {
      name   = "cynews"
      image  = local.image
      cpu    = 0.5
      memory = "1Gi"
      args   = ["serve"]

      dynamic "env" {
        for_each = local.env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.secret_names
        content {
          name        = local.secrets[env.value].env
          secret_name = env.value
        }
      }

      liveness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/healthz"
      }
      readiness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/healthz"
      }
    }

    http_scale_rule {
      name                = "http"
      concurrent_requests = "50"
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull, azurerm_role_assignment.kv_app]
}

# Scheduled jobs: hourly aggregation and the daily digest.
resource "azurerm_container_app_job" "job" {
  for_each = {
    aggregate = { cron = var.fetch_cron_utc, timeout = 3300, args = ["run"] }
    digest    = { cron = var.digest_cron_utc, timeout = 900, args = ["digest"] }
  }

  name                         = "caj-${var.name}-${each.key}"
  location                     = azurerm_resource_group.rg.location
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  replica_timeout_in_seconds   = each.value.timeout
  replica_retry_limit          = 1
  tags                         = var.tags

  schedule_trigger_config {
    cron_expression          = each.value.cron
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = azurerm_user_assigned_identity.app.id
  }

  dynamic "secret" {
    for_each = local.secret_names
    content {
      name                = secret.key
      key_vault_secret_id = azurerm_key_vault_secret.s[secret.key].versionless_id
      identity            = azurerm_user_assigned_identity.app.id
    }
  }

  template {
    container {
      name   = "cynews"
      image  = local.image
      cpu    = 0.5
      memory = "1Gi"
      args   = each.value.args

      dynamic "env" {
        for_each = local.env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.secret_names
        content {
          name        = local.secrets[env.value].env
          secret_name = env.value
        }
      }
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull, azurerm_role_assignment.kv_app]
}
