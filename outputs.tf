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

output "domain_name" {
  description = "Custom domain name configured for the HTTPS Application Load Balancer"
  value       = var.domain_name
}

output "ssl_cert_name" {
  description = "Name of the Google-managed SSL certificate"
  value       = google_compute_managed_ssl_certificate.ssl_cert.name
}

output "https_url" {
  description = "Base HTTPS URL of the Global Application Load Balancer"
  value       = "https://${var.domain_name}"
}

output "mig_name" {
  description = "Name of the Managed Instance Group running backend VMs"
  value       = google_compute_instance_group_manager.backend_mig.name
}

output "vpc_name" {
  description = "Name of the Custom Enterprise VPC Network"
  value       = google_compute_network.vpc.name
}

