output "api_url" {
  description = "Public HTTPS URL of the sigil-api Container App."
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "dashboard_url" {
  description = "Public HTTPS URL of the sigil-dashboard Container App."
  value       = "https://${azurerm_container_app.dashboard.ingress[0].fqdn}"
}

output "acr_login_server" {
  description = "Login server hostname for the Azure Container Registry."
  value       = azurerm_container_registry.acr.login_server
}

output "acr_admin_username" {
  description = "Admin username for the Azure Container Registry."
  value       = azurerm_container_registry.acr.admin_username
}

output "database_url" {
  description = "PostgreSQL connection string passed in via variable (e.g. Supabase). Handle with care."
  value       = local.database_url
  sensitive   = true
}

output "redis_url" {
  description = "Full Redis connection string including the primary access key. Handle with care."
  value       = local.redis_url
  sensitive   = true
}

output "resource_group_name" {
  description = "Name of the Azure resource group containing all Sigil resources."
  value       = azurerm_resource_group.rg.name
}

output "key_vault_name" {
  description = "Name of the Azure Key Vault storing Sigil secrets."
  value       = azurerm_key_vault.kv.name
}
