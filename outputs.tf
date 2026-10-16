# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: outputs.tf
# ==============================================================================

output "lb_external_ip" {
  description = "Global Anycast External IPv4 Address of the Application Load Balancer"
  value       = google_compute_global_address.lb_ip.address
}

output "backend_service_name" {
  description = "Name of the Backend Service protected by Google Cloud Armor"
  value       = google_compute_backend_service.backend_service.name
}

output "security_policy_name" {
  description = "Name of the attached Google Cloud Armor Security Policy"
  value       = google_compute_security_policy.waf_policy.name
}

output "lb_base_url" {
  description = "Base HTTP URL of the Global Application Load Balancer"
  value       = "http://${google_compute_global_address.lb_ip.address}"
}

output "mig_name" {
  description = "Name of the Managed Instance Group running backend VMs"
  value       = google_compute_instance_group_manager.backend_mig.name
}

output "vpc_name" {
  description = "Name of the Custom Enterprise VPC Network"
  value       = google_compute_network.vpc.name
}
