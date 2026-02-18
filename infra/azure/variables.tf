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

variable "db_admin_user" {
  description = "Administrator login username for the PostgreSQL Flexible Server."
  type        = string
  default     = "sigiladmin"
}

variable "db_admin_password" {
  description = "Administrator login password for the PostgreSQL Flexible Server. Must meet Azure complexity requirements."
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
