# ─── Account ────────────────────────────────────────────────────────────────

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = "ac7254fa-1f0b-433e-976c-b0430909c5ac"
}

variable "tenant_id" {
  description = "Azure tenant ID"
  type        = string
  default     = "2601808d-88e3-4af3-a6b8-377f2c915782"
}

# ─── Environment ─────────────────────────────────────────────────────────────

variable "environment" {
  description = "Deployment environment: dev or prod"
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be 'dev' or 'prod'."
  }
}

variable "location" {
  description = "Azure region for Sigil resources"
  type        = string
  default     = "australiaeast"
}

# ─── Tags ────────────────────────────────────────────────────────────────────

variable "cost_center" {
  description = "Cost center code for billing allocation"
  type        = string
  default     = "sigil"
}

variable "owner" {
  description = "Team or individual responsible for these resources"
  type        = string
  default     = "reece@nomark.au"
}
