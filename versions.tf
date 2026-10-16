# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: versions.tf
# ==============================================================================

terraform {
  required_version = ">= 1.3.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "tfstate-hitachi-lab-dev-robifirmansyah"
    prefix = "smg-cloud-armor-demo"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
