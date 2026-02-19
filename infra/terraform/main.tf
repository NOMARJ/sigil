# ─── Locals ──────────────────────────────────────────────────────────────────

locals {
  # Consistent naming prefix: sigil-<env>
  prefix = "sigil-${var.environment}"

  # Tags applied to every Sigil resource
  common_tags = {
    product     = "sigil"
    environment = var.environment
    cost_center = var.cost_center
    owner       = var.owner
    managed_by  = "terraform"
    repo        = "github.com/NOMARJ/sigil"
  }
}

# ─── Resource Groups ─────────────────────────────────────────────────────────

# Core application resources (API, compute, storage)
resource "azurerm_resource_group" "app" {
  name     = "${local.prefix}-app-rg"
  location = var.location
  tags     = merge(local.common_tags, { tier = "app" })
}

# Networking (VNets, NSGs, private endpoints)
resource "azurerm_resource_group" "network" {
  name     = "${local.prefix}-network-rg"
  location = var.location
  tags     = merge(local.common_tags, { tier = "network" })
}

# Data resources (databases, storage accounts, key vault)
resource "azurerm_resource_group" "data" {
  name     = "${local.prefix}-data-rg"
  location = var.location
  tags     = merge(local.common_tags, { tier = "data" })
}

# Monitoring and observability (Log Analytics, Application Insights)
resource "azurerm_resource_group" "monitoring" {
  name     = "${local.prefix}-monitoring-rg"
  location = var.location
  tags     = merge(local.common_tags, { tier = "monitoring" })
}
