output "resource_groups" {
  description = "All Sigil resource group names and IDs"
  value = {
    app = {
      name = azurerm_resource_group.app.name
      id   = azurerm_resource_group.app.id
    }
    network = {
      name = azurerm_resource_group.network.name
      id   = azurerm_resource_group.network.id
    }
    data = {
      name = azurerm_resource_group.data.name
      id   = azurerm_resource_group.data.id
    }
    monitoring = {
      name = azurerm_resource_group.monitoring.name
      id   = azurerm_resource_group.monitoring.id
    }
  }
}

output "common_tags" {
  description = "Tag set applied to all Sigil resources in this environment"
  value       = local.common_tags
}

output "location" {
  description = "Azure region for this Sigil deployment"
  value       = var.location
}
