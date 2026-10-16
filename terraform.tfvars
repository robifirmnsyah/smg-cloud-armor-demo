# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: terraform.tfvars
# ==============================================================================

project_id  = "dev-robifirmansyah"
region      = "asia-southeast2"
zone        = "asia-southeast2-a"
name_prefix = "smg-armor"

subnet_cidr       = "10.30.0.0/24"
proxy_subnet_cidr = "10.30.1.0/24"
machine_type      = "e2-medium"
mig_target_size   = 2

rate_limit_count            = 50
rate_limit_interval_sec     = 60
rate_limit_ban_duration_sec = 300
