terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }

  # Uncomment and configure once you have a storage account for remote state
  # backend "azurerm" {
  #   resource_group_name  = "nomark-devops-rg"
  #   storage_account_name = "<your_storage_account>"
  #   container_name       = "tfstate"
  #   key                  = "sigil/terraform.tfstate"
  # }
}

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}
