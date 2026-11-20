# Entra ID sign-in via Container Apps built-in authentication ("Easy Auth").
# Only users in your tenant can reach the SPA and API; /healthz stays open.

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "msgraph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

resource "azuread_application" "auth" {
  count            = var.enable_auth ? 1 : 0
  display_name     = "CyNewsFeed (${var.name})"
  sign_in_audience = "AzureADMyOrg"
  identifier_uris  = []

  web {
    homepage_url  = local.app_url
    redirect_uris = ["${local.app_url}/.auth/login/aad/callback"]
    implicit_grant {
      id_token_issuance_enabled = true
    }
  }

  required_resource_access {
    resource_app_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
    resource_access {
      id   = data.azuread_service_principal.msgraph.oauth2_permission_scope_ids["User.Read"]
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "auth" {
  count     = var.enable_auth ? 1 : 0
  client_id = azuread_application.auth[0].client_id
}

resource "azuread_application_password" "auth" {
  count          = var.enable_auth ? 1 : 0
  application_id = azuread_application.auth[0].id
  display_name   = "container-apps-easy-auth"
  end_date       = timeadd(timestamp(), "8760h") # 1 year; re-apply to rotate

  lifecycle {
    ignore_changes = [end_date]
  }
}

resource "azapi_resource" "auth_config" {
  count     = var.enable_auth ? 1 : 0
  type      = "Microsoft.App/containerApps/authConfigs@2024-03-01"
  name      = "current"
  parent_id = azurerm_container_app.app.id

  body = {
    properties = {
      platform = { enabled = true }
      globalValidation = {
        unauthenticatedClientAction = "RedirectToLoginPage"
        redirectToProvider          = "azureactivedirectory"
        # Machine endpoints authenticate with their own tokens (TAXII_TOKEN / MCP_TOKEN).
        excludedPaths = ["/healthz", "/mcp", "/taxii2", "/taxii2/*"]
      }
      identityProviders = {
        azureActiveDirectory = {
          enabled = true
          registration = {
            clientId                = azuread_application.auth[0].client_id
            clientSecretSettingName = "microsoft-provider-authentication-secret"
            openIdIssuer            = "https://login.microsoftonline.com/${data.azurerm_client_config.current.tenant_id}/v2.0"
          }
          validation = {
            allowedAudiences = [azuread_application.auth[0].client_id]
          }
        }
      }
      login = { preserveUrlFragmentsForLogins = true }
    }
  }
}
