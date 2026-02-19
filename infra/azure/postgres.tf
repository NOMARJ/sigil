# PostgreSQL is provided externally (Supabase or any managed Postgres).
# Pass the full connection string via the database_url variable.
# This file is intentionally empty — no Azure Postgres resources are provisioned.

locals {
  database_url = var.database_url
}
