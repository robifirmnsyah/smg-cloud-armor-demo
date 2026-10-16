# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: variables.tf
# ==============================================================================

variable "project_id" {
  description = "Google Cloud Project ID for SMG Cloud Armor Enterprise Demo"
  type        = string
  default     = "dev-robifirmansyah"
}

variable "region" {
  description = "Primary GCP Region (Jakarta)"
  type        = string
  default     = "asia-southeast2"
}

variable "zone" {
  description = "Primary GCP Zone in Jakarta region"
  type        = string
  default     = "asia-southeast2-a"
}

variable "name_prefix" {
  description = "Resource naming prefix for all SMG Cloud Armor demo resources"
  type        = string
  default     = "smg-armor"
}

variable "subnet_cidr" {
  description = "Primary CIDR range for backend workload subnet in Jakarta"
  type        = string
  default     = "10.30.0.0/24"
}

variable "proxy_subnet_cidr" {
  description = "CIDR range for Regional Managed Proxy-Only subnet"
  type        = string
  default     = "10.30.1.0/24"
}

variable "machine_type" {
  description = "Compute Engine machine type for backend MIG instances"
  type        = string
  default     = "e2-medium"
}

variable "mig_target_size" {
  description = "Number of backend instances in the Managed Instance Group"
  type        = number
  default     = 2
}

variable "rate_limit_count" {
  description = "Maximum allowed requests per interval per client IP before rate-based ban"
  type        = number
  default     = 50
}

variable "rate_limit_interval_sec" {
  description = "Interval window in seconds for rate limiting evaluation"
  type        = number
  default     = 60
}

variable "rate_limit_ban_duration_sec" {
  description = "Ban duration in seconds once client IP exceeds rate limit threshold"
  type        = number
  default     = 300
}

variable "domain_name" {
  description = "Custom domain name for Google-managed SSL certificate and HTTPS Load Balancer"
  type        = string
  default     = "armor.cloudwithmagna.com"
}

