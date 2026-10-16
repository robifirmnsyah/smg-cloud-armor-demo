# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: network.tf
# ==============================================================================

# 1. Custom VPC Network
resource "google_compute_network" "vpc" {
  name                    = "${var.name_prefix}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Enterprise Custom VPC for SMG Cloud Armor WAF & L7 DDoS Demo"
}

# 2. Primary Backend Subnet (Jakarta - asia-southeast2)
resource "google_compute_subnetwork" "backend_subnet" {
  name                     = "${var.name_prefix}-subnet"
  ip_cidr_range            = var.subnet_cidr
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true
  description              = "Primary backend workload subnet in Jakarta (Zero External IP)"
}

# 3. Regional Managed Proxy-Only Subnet for Envoy-based Load Balancing
resource "google_compute_subnetwork" "proxy_subnet" {
  name          = "${var.name_prefix}-proxy-subnet"
  ip_cidr_range = var.proxy_subnet_cidr
  region        = var.region
  network       = google_compute_network.vpc.id
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
  description   = "Proxy-only subnet for Regional Envoy Managed Proxies"
}

# 4. Cloud Router & Cloud NAT (Outbound Internet Access for Zero-Public-IP VMs)
resource "google_compute_router" "router" {
  name    = "${var.name_prefix}-router"
  region  = var.region
  network = google_compute_network.vpc.id

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.name_prefix}-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# 5. Firewall Rule: Allow Google Cloud Health Check Probes & GFE Proxies
resource "google_compute_firewall" "allow_health_check" {
  name        = "${var.name_prefix}-allow-health-check"
  network     = google_compute_network.vpc.name
  direction   = "INGRESS"
  priority    = 1000
  description = "Allow Google Cloud Load Balancer health check probes and GFE ranges"

  allow {
    protocol = "tcp"
    ports    = ["80", "8080"]
  }

  source_ranges = [
    "130.211.0.0/22",
    "35.191.0.0/16"
  ]

  target_tags = ["${var.name_prefix}-backend"]
}

# 6. Firewall Rule: Allow Envoy Proxy-Only Subnet Traffic to Backend
resource "google_compute_firewall" "allow_proxy" {
  name        = "${var.name_prefix}-allow-proxy"
  network     = google_compute_network.vpc.name
  direction   = "INGRESS"
  priority    = 1000
  description = "Allow traffic from Regional Managed Proxy subnet to backend instances"

  allow {
    protocol = "tcp"
    ports    = ["80", "8080"]
  }

  source_ranges = [var.proxy_subnet_cidr]
  target_tags   = ["${var.name_prefix}-backend"]
}

# 7. Firewall Rule: Allow Zero-Trust SSH via Identity-Aware Proxy (IAP)
resource "google_compute_firewall" "allow_iap_ssh" {
  name        = "${var.name_prefix}-allow-iap-ssh"
  network     = google_compute_network.vpc.name
  direction   = "INGRESS"
  priority    = 1000
  description = "Allow administrative SSH access exclusively via Google Cloud IAP"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["${var.name_prefix}-backend"]
}
