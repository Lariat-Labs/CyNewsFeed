output "app_url" {
  value = local.app_url
}

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "acr_name" {
  value = azurerm_container_registry.acr.name
}

output "acr_login_server" {
  value = azurerm_container_registry.acr.login_server
}

output "storage_account" {
  value = azurerm_storage_account.st.name
}

output "aggregate_job" {
  value = azurerm_container_app_job.job["aggregate"].name
}

output "digest_job" {
  value = azurerm_container_app_job.job["digest"].name
}

output "taxii_api_root" {
  value = "${local.app_url}/taxii2/api/"
}

output "mcp_url" {
  value = "${local.app_url}/mcp"
}

output "taxii_token" {
  value     = random_password.taxii.result
  sensitive = true
}

output "mcp_token" {
  value     = random_password.mcp.result
  sensitive = true
}
