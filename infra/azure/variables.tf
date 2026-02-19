variable "location" {
  description = "Azure region where all resources will be deployed."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Name of the Azure resource group that contains all Sigil resources."
  type        = string
  default     = "sigil-rg"
}

variable "environment" {
  description = "Deployment environment label (e.g. production, staging)."
  type        = string
  default     = "production"
}

variable "app_name" {
  description = "Base application name used in resource naming."
  type        = string
  default     = "sigil"
}

variable "database_url" {
  description = "Full PostgreSQL connection string (e.g. from Supabase). Format: postgresql://user:pass@host:5432/db?sslmode=require"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "Secret key used to sign and verify JWT tokens. Generate with: openssl rand -hex 32"
  type        = string
  sensitive   = true
}

variable "cors_origins" {
  description = "JSON-encoded list of allowed CORS origins for the API."
  type        = string
  default     = "[\"https://sigil.example.com\"]"
}

variable "smtp_host" {
  description = "SMTP server hostname for outbound email. Leave empty to disable email."
  type        = string
  default     = ""
}

variable "smtp_port" {
  description = "SMTP server port."
  type        = number
  default     = 587
}

variable "smtp_user" {
  description = "SMTP authentication username."
  type        = string
  default     = ""
}

variable "smtp_password" {
  description = "SMTP authentication password."
  type        = string
  sensitive   = true
  default     = ""
}

variable "smtp_from_email" {
  description = "From address used for outbound email."
  type        = string
  default     = ""
}

variable "stripe_secret_key" {
  description = "Stripe live secret key (sk_live_...)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "stripe_webhook_secret" {
  description = "Stripe webhook signing secret (whsec_...)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "stripe_price_pro" {
  description = "Stripe Price ID for the Pro plan."
  type        = string
  default     = ""
}

variable "stripe_price_team" {
  description = "Stripe Price ID for the Team plan."
  type        = string
  default     = ""
}

variable "api_min_replicas" {
  description = "Minimum replica count for the sigil-api Container App. Set to 0 to scale to zero when idle."
  type        = number
  default     = 0
}

variable "api_max_replicas" {
  description = "Maximum replica count for the sigil-api Container App."
  type        = number
  default     = 3
}

variable "dashboard_min_replicas" {
  description = "Minimum replica count for the sigil-dashboard Container App. Set to 0 to scale to zero when idle."
  type        = number
  default     = 0
}

variable "dashboard_max_replicas" {
  description = "Maximum replica count for the sigil-dashboard Container App."
  type        = number
  default     = 2
}
