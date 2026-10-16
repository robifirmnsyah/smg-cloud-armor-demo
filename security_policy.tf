# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: security_policy.tf
# ==============================================================================

resource "google_compute_security_policy" "waf_policy" {
  name        = "${var.name_prefix}-waf-policy"
  description = "SMG Enterprise Cloud Armor WAF Policy: OWASP Top 10 Preconfigured Rules & Layer 7 DDoS Rate Limiting"
  type        = "CLOUD_ARMOR"

  # Enable Verbose Logging & Standard JSON Body Parsing for Deep L7 Inspection
  advanced_options_config {
    json_parsing = "STANDARD"
    log_level    = "VERBOSE"
  }

  # Enable Cloud Armor Adaptive Protection for Layer 7 DDoS Defense
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = true
      rule_visibility = "STANDARD"
    }
  }

  # ----------------------------------------------------------------------------
  # Rule Priority 1000: SQL Injection (SQLi) Mitigation
  # ----------------------------------------------------------------------------
  rule {
    action      = "deny(403)"
    priority    = 1000
    description = "OWASP Top 10 - Block SQL Injection (SQLi) via ModSecurity CRS v3.3"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
  }

  # ----------------------------------------------------------------------------
  # Rule Priority 1010: Cross-Site Scripting (XSS) Mitigation
  # ----------------------------------------------------------------------------
  rule {
    action      = "deny(403)"
    priority    = 1010
    description = "OWASP Top 10 - Block Cross-Site Scripting (XSS) via ModSecurity CRS v3.3"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
  }

  # ----------------------------------------------------------------------------
  # Rule Priority 1020: Local & Remote File Inclusion (LFI / RFI) Mitigation
  # ----------------------------------------------------------------------------
  rule {
    action      = "deny(403)"
    priority    = 1020
    description = "OWASP Top 10 - Block Local & Remote File Inclusion (LFI/RFI) Attacks"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable') || evaluatePreconfiguredExpr('rfi-v33-stable')"
      }
    }
  }

  # ----------------------------------------------------------------------------
  # Rule Priority 1030: Remote Code Execution (RCE) / Command Injection
  # ----------------------------------------------------------------------------
  rule {
    action      = "deny(403)"
    priority    = 1030
    description = "OWASP Top 10 - Block Remote Code Execution (RCE) & OS Command Injection"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }
  }

  # ----------------------------------------------------------------------------
  # Rule Priority 1040: Automated Scanner & Vulnerability Probe Detection
  # ----------------------------------------------------------------------------
  rule {
    action      = "deny(403)"
    priority    = 1040
    description = "OWASP Top 10 - Block Automated Security Scanners & Vulnerability Probes"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }
  }

  # ----------------------------------------------------------------------------
  # Rule Priority 2000: Layer 7 DDoS Mitigation & Rate-Based Ban
  # ----------------------------------------------------------------------------
  rule {
    action      = "rate_based_ban"
    priority    = 2000
    description = "Layer 7 Rate Limiting: Max 50 requests/min per IP, ban 300s with HTTP 429"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }

    rate_limit_options {
      conform_action   = "allow"
      exceed_action    = "deny(429)"
      enforce_on_key   = "IP"
      ban_duration_sec = var.rate_limit_ban_duration_sec

      rate_limit_threshold {
        count        = var.rate_limit_count
        interval_sec = var.rate_limit_interval_sec
      }
    }
  }

  # ----------------------------------------------------------------------------
  # Rule Priority 2147483647: Default Rule Allow Legitimate Traffic
  # ----------------------------------------------------------------------------
  rule {
    action      = "allow"
    priority    = 2147483647
    description = "Default rule: Allow legitimate traffic passing all WAF & Rate Limit checks"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}
