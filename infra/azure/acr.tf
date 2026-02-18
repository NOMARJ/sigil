resource "azurerm_container_registry" "acr" {
  name                = "sigilacr${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Basic"
  admin_enabled       = true

  tags = local.tags
}

# Store ACR admin credentials in Key Vault so Container Apps can reference them
# without embedding plaintext credentials in the container app configuration.
resource "azurerm_key_vault_secret" "acr_username" {
  name         = "sigil-acr-username"
  value        = azurerm_container_registry.acr.admin_username
  key_vault_id = azurerm_key_vault.kv.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
}

resource "azurerm_key_vault_secret" "acr_password" {
  name         = "sigil-acr-password"
  value        = azurerm_container_registry.acr.admin_password
  key_vault_id = azurerm_key_vault.kv.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
}
