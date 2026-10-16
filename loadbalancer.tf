# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: loadbalancer.tf
# ==============================================================================

# 1. Global Static Anycast External IPv4 Address
resource "google_compute_global_address" "lb_ip" {
  name         = "${var.name_prefix}-anycast-ip"
  ip_version   = "IPV4"
  address_type = "EXTERNAL"
  description  = "Global Anycast External IP for SMG Cloud Armor Enterprise WAF Demo"
}

# 2. HTTP Health Check (/health -> 200 OK)
resource "google_compute_health_check" "http_health_check" {
  name                = "${var.name_prefix}-http-hc"
  description         = "HTTP Health Check probing /health on backend instances"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 80
    port_name    = "http"
    request_path = "/health"
  }

  log_config {
    enable = true
  }
}

# 3. Backend Service with Cloud Armor WAF Security Policy & Full Telemetry Logging
resource "google_compute_backend_service" "backend_service" {
  name                  = "${var.name_prefix}-backend-svc"
  description           = "Enterprise Backend Service protected by Google Cloud Armor WAF Policy"
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  enable_cdn            = false

  # Attach Google Cloud Armor WAF & L7 DDoS Security Policy
  security_policy = google_compute_security_policy.waf_policy.id

  health_checks = [
    google_compute_health_check.http_health_check.id
  ]

  backend {
    group           = google_compute_instance_group_manager.backend_mig.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
    max_utilization = 0.8
  }

  # Enable 100% Sampling Rate for Cloud Armor Security Audit Logging
  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

# 4. URL Map Routing Traffic to Protected Backend Service
resource "google_compute_url_map" "url_map" {
  name            = "${var.name_prefix}-url-map"
  description     = "Global URL Map for SMG Cloud Armor Demo"
  default_service = google_compute_backend_service.backend_service.id
}

# 5. Target HTTP Proxy
resource "google_compute_target_http_proxy" "http_proxy" {
  name        = "${var.name_prefix}-http-proxy"
  description = "Target HTTP Proxy for Global External Application Load Balancer"
  url_map     = google_compute_url_map.url_map.id
}

# 6. Global Forwarding Rule (Port 80 -> Target HTTP Proxy)
resource "google_compute_global_forwarding_rule" "http_forwarding_rule" {
  name                  = "${var.name_prefix}-http-fwd-rule"
  description           = "Global Anycast HTTP Forwarding Rule on Port 80"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.http_proxy.id
  ip_address            = google_compute_global_address.lb_ip.id
}
