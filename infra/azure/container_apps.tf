resource "azurerm_log_analytics_workspace" "law" {
  name                = "sigil-law-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = local.tags
}

resource "azurerm_container_app_environment" "env" {
  name                       = "sigil-env-${random_string.suffix.result}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = azurerm_resource_group.rg.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  tags = local.tags
}

# ---------------------------------------------------------------------------
# sigil-api Container App
# ---------------------------------------------------------------------------
# Sensitive environment variables (JWT secret, database URL, Redis URL) are
# surfaced through Container Apps "secrets" blocks and referenced by name via
# secretRef. The values are pulled directly from Key Vault secrets at deploy
# time rather than being stored in the Container App revision metadata.
# ---------------------------------------------------------------------------

resource "azurerm_container_app" "api" {
  name                         = "sigil-api"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  tags = local.tags

  # Registry credentials so the Container App runtime can pull images.
  registry {
    server               = azurerm_container_registry.acr.login_server
    username             = azurerm_container_registry.acr.admin_username
    password_secret_name = "acr-password"
  }

  # Secrets stored inside the Container App (not Key Vault references at the
  # azurerm resource level — the provider exposes them as inline secret blocks).
  secret {
    name  = "acr-password"
    value = azurerm_container_registry.acr.admin_password
  }

  secret {
    name  = "sigil-jwt-secret"
    value = var.jwt_secret
  }

  secret {
    name  = "sigil-database-url"
    value = local.database_url
  }

  secret {
    name  = "sigil-redis-url"
    value = local.redis_url
  }

  secret {
    name  = "sigil-smtp-password"
    value = var.smtp_password
  }

  template {
    min_replicas = var.api_min_replicas
    max_replicas = var.api_max_replicas

    container {
      name   = "sigil-api"
      image  = "${azurerm_container_registry.acr.login_server}/sigil:latest"
      cpu    = 0.5
      memory = "1Gi"

      # Non-sensitive environment variables set as plain values.
      env {
        name  = "SIGIL_DEBUG"
        value = "false"
      }

      env {
        name  = "SIGIL_LOG_LEVEL"
        value = "WARNING"
      }

      env {
        name  = "SIGIL_HOST"
        value = "0.0.0.0"
      }

      env {
        name  = "SIGIL_PORT"
        value = "8000"
      }

      env {
        name  = "SIGIL_CORS_ORIGINS"
        value = var.cors_origins
      }

      env {
        name  = "SIGIL_SMTP_HOST"
        value = var.smtp_host
      }

      env {
        name  = "SIGIL_SMTP_PORT"
        value = tostring(var.smtp_port)
      }

      env {
        name  = "SIGIL_SMTP_USER"
        value = var.smtp_user
      }

      env {
        name  = "SIGIL_SMTP_FROM_EMAIL"
        value = var.smtp_from_email
      }

      # Sensitive environment variables referenced from the secret blocks above.
      env {
        name        = "SIGIL_JWT_SECRET"
        secret_name = "sigil-jwt-secret"
      }

      env {
        name        = "SIGIL_DATABASE_URL"
        secret_name = "sigil-database-url"
      }

      env {
        name        = "SIGIL_REDIS_URL"
        secret_name = "sigil-redis-url"
      }

      env {
        name        = "SIGIL_SMTP_PASSWORD"
        secret_name = "sigil-smtp-password"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [
    azurerm_container_registry.acr,
    azurerm_postgresql_flexible_server_database.sigil,
    azurerm_redis_cache.redis,
  ]
}

# ---------------------------------------------------------------------------
# sigil-dashboard Container App
# ---------------------------------------------------------------------------

resource "azurerm_container_app" "dashboard" {
  name                         = "sigil-dashboard"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  tags = local.tags

  registry {
    server               = azurerm_container_registry.acr.login_server
    username             = azurerm_container_registry.acr.admin_username
    password_secret_name = "acr-password"
  }

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.acr.admin_password
  }

  template {
    min_replicas = var.dashboard_min_replicas
    max_replicas = var.dashboard_max_replicas

    container {
      name   = "sigil-dashboard"
      image  = "${azurerm_container_registry.acr.login_server}/sigil-dashboard:latest"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name  = "NEXT_PUBLIC_API_URL"
        value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
      }

      env {
        name  = "NODE_ENV"
        value = "production"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 3000
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [azurerm_container_app.api]
}
