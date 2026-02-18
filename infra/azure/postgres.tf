resource "azurerm_postgresql_flexible_server" "postgres" {
  name                   = "sigil-postgres-${random_string.suffix.result}"
  resource_group_name    = azurerm_resource_group.rg.name
  location               = azurerm_resource_group.rg.location
  version                = "16"
  sku_name               = "B_Standard_B1ms"
  storage_mb             = 32768
  backup_retention_days  = 7
  geo_redundant_backup_enabled = false
  zone                   = "1"

  administrator_login    = var.db_admin_user
  administrator_password = var.db_admin_password

  tags = local.tags
}

resource "azurerm_postgresql_flexible_server_database" "sigil" {
  name      = "sigil"
  server_id = azurerm_postgresql_flexible_server.postgres.id
  charset   = "utf8"
  collation = "en_US.utf8"
}

# Disable require_secure_transport to simplify initial connectivity from
# Container Apps. Azure Container Apps communicate over the Azure backbone
# but the PgBouncer/driver path does not always present certs in the right
# order. Re-enable (value = "on") once TLS certificates are validated.
resource "azurerm_postgresql_flexible_server_configuration" "ssl" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.postgres.id
  value     = "off"
}

# The magic IP range 0.0.0.0-0.0.0.0 is an Azure-documented shorthand that
# permits all Azure-hosted services (including Container Apps) to connect
# without opening the server to the public internet.
resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure_services" {
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.postgres.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

locals {
  database_url = "postgresql://${var.db_admin_user}:${var.db_admin_password}@${azurerm_postgresql_flexible_server.postgres.fqdn}:5432/sigil"
}
