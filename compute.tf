# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: compute.tf
# ==============================================================================

locals {
  backend_startup_script = <<-EOF
    #!/bin/bash
    set -e

    mkdir -p /opt/smg-app

    cat <<'PYEOF' > /opt/smg-app/app.py
    #!/usr/bin/env python3
    """
    SMG Enterprise Security Demo Backend Server
    Serves simulated enterprise endpoints behind Google Cloud Armor WAF:
      - GET  /                : Welcome page SMG Security Demo
      - GET  /api/search?q=.. : Search simulation endpoint (SQLi / XSS target)
      - POST /api/comment     : Comment submission simulation (XSS / RCE target)
      - GET  /api/view?file=. : Document viewer simulation (LFI / RFI / Path Traversal target)
      - GET  /health          : Load Balancer Health Check (200 OK)
    """
    import json
    import os
    import socket
    from datetime import datetime, timezone
    from urllib.parse import parse_qs, urlparse

    HOSTNAME = socket.gethostname()

    WELCOME_HTML = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>SMG Security Demo | Google Cloud Armor Enterprise WAF</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .card {{ max-width: 820px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }}
        .badge {{ display: inline-block; background: #0ea5e9; color: #0f172a; font-weight: 700; padding: 4px 12px; border-radius: 9999px; font-size: 12px; letter-spacing: 0.05em; text-transform: uppercase; }}
        h1 {{ margin-top: 16px; font-size: 28px; color: #38bdf8; }}
        p {{ color: #cbd5e1; line-height: 1.6; }}
        .meta {{ background: #0f172a; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 14px; color: #4ade80; margin: 20px 0; }}
        ul {{ color: #94a3b8; line-height: 1.8; }}
        code {{ background: #334155; color: #f8fafc; padding: 2px 6px; border-radius: 4px; }}
      </style>
    </head>
    <body>
      <div class="card">
        <span class="badge">PT Smartnet Magna Global (SMG) &bull; Google Cloud Premier Partner</span>
        <h1>Welcome Page - SMG Security Demo</h1>
        <p>This backend application is protected by <strong>Google Cloud Armor Enterprise WAF</strong> &amp; <strong>Layer 7 DDoS Mitigation</strong> running on a Zero-External-IP Managed Instance Group in Jakarta (<code>asia-southeast2</code>).</p>
        <div class="meta">
          Backend Node : {HOSTNAME}<br/>
          Security Tier: Cloud Armor WAF + Rate Limiting Active<br/>
          Network Mode : Private VPC (Zero Public IP)
        </div>
        <h3>Available Simulation Endpoints:</h3>
        <ul>
          <li><code>GET /</code> &mdash; Welcome page SMG Security Demo</li>
          <li><code>GET /api/search?q=...</code> &mdash; Enterprise catalog search simulation</li>
          <li><code>POST /api/comment</code> &mdash; Customer feedback / comment simulation</li>
          <li><code>GET /api/view?file=...</code> &mdash; Internal document viewer simulation</li>
          <li><code>GET /health</code> &mdash; GFE Load Balancer health check probe</li>
        </ul>
      </div>
    </body>
    </html>
    """

    try:
        from flask import Flask, jsonify, request, Response

        app = Flask(__name__)

        @app.route("/", methods=["GET"])
        def index():
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({
                    "status": "success",
                    "message": "Welcome page SMG Security Demo",
                    "partner": "PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner",
                    "backend_instance": HOSTNAME,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }), 200
            return Response(WELCOME_HTML, status=200, mimetype="text/html")

        @app.route("/api/search", methods=["GET"])
        def api_search():
            query = request.args.get("q", "")
            return jsonify({
                "status": "success",
                "endpoint": "/api/search",
                "query": query,
                "results": [
                    {"id": 101, "title": f"SMG Cloud Security Reference for '{query}'", "category": "WAF & DDoS"},
                    {"id": 102, "title": "Google Cloud Armor OWASP Top 10 Mitigation Guide", "category": "Security"}
                ],
                "served_by": HOSTNAME,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200

        @app.route("/api/comment", methods=["POST"])
        def api_comment():
            payload = request.get_json(silent=True) or request.form.to_dict() or request.get_data(as_text=True)
            return jsonify({
                "status": "success",
                "endpoint": "/api/comment",
                "message": "Comment sanitized and stored in simulation log",
                "comment_received": payload,
                "served_by": HOSTNAME,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200

        @app.route("/api/view", methods=["GET"])
        def api_view():
            filename = request.args.get("file", "readme.txt")
            return jsonify({
                "status": "success",
                "endpoint": "/api/view",
                "file": filename,
                "content": f"Simulated document preview for [{filename}] - Verified safe by SMG Cloud Armor Policy.",
                "served_by": HOSTNAME,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200

        @app.route("/health", methods=["GET"])
        def health():
            return jsonify({
                "status": "200 OK",
                "healthy": True,
                "service": "smg-armor-backend",
                "served_by": HOSTNAME
            }), 200

        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=80, threaded=True)

    except ImportError:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class SMGDemoHandler(BaseHTTPRequestHandler):
            def _send_json(self, code, data):
                body = json.dumps(data).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                if parsed.path == "/":
                    if "application/json" in self.headers.get("Accept", ""):
                        self._send_json(200, {
                            "status": "success",
                            "message": "Welcome page SMG Security Demo",
                            "partner": "PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner",
                            "backend_instance": HOSTNAME,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                    else:
                        body = WELCOME_HTML.encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                elif parsed.path == "/api/search":
                    q = params.get("q", [""])[0]
                    self._send_json(200, {
                        "status": "success",
                        "endpoint": "/api/search",
                        "query": q,
                        "results": [
                            {"id": 101, "title": f"SMG Cloud Security Reference for '{q}'", "category": "WAF & DDoS"}
                        ],
                        "served_by": HOSTNAME,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                elif parsed.path == "/api/view":
                    f_param = params.get("file", ["readme.txt"])[0]
                    self._send_json(200, {
                        "status": "success",
                        "endpoint": "/api/view",
                        "file": f_param,
                        "content": f"Simulated document preview for [{f_param}]",
                        "served_by": HOSTNAME,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                elif parsed.path == "/health":
                    self._send_json(200, {
                        "status": "200 OK",
                        "healthy": True,
                        "service": "smg-armor-backend",
                        "served_by": HOSTNAME
                    })
                else:
                    self._send_json(404, {"status": "error", "message": "Not Found", "path": parsed.path})

            def do_POST(self):
                parsed = urlparse(self.path)
                length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
                if parsed.path == "/api/comment":
                    self._send_json(200, {
                        "status": "success",
                        "endpoint": "/api/comment",
                        "comment_received": raw_body,
                        "served_by": HOSTNAME,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                else:
                    self._send_json(404, {"status": "error", "message": "Not Found", "path": parsed.path})

        if __name__ == "__main__":
            server = ThreadingHTTPServer(("0.0.0.0", 80), SMGDemoHandler)
            server.serve_forever()
    PYEOF

    chmod +x /opt/smg-app/app.py

    cat <<'SVCEOF' > /etc/systemd/system/smg-web.service
    [Unit]
    Description=SMG Cloud Armor Demo Python Web Server
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/opt/smg-app
    ExecStart=/usr/bin/python3 /opt/smg-app/app.py
    Restart=always
    RestartSec=2

    [Install]
    WantedBy=multi-user.target
    SVCEOF

    # Start immediately using stdlib fallback so Health Check responds in seconds
    systemctl daemon-reload
    systemctl enable smg-web.service
    systemctl start smg-web.service

    # Install Python3 Flask via Cloud NAT and restart service with Flask active
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y && apt-get install -y python3-flask && systemctl restart smg-web.service || true
  EOF
}

# 1. Instance Template (Zero Public IP - Internal VPC Only)
resource "google_compute_instance_template" "backend_template" {
  name_prefix  = "${var.name_prefix}-tpl-"
  machine_type = var.machine_type
  region       = var.region
  description  = "Zero-External-IP instance template for SMG Cloud Armor Backend MIG"

  tags = ["${var.name_prefix}-backend"]

  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true
    disk_size_gb = 20
    disk_type    = "pd-balanced"
  }

  # Zero External IP: No access_config block specified
  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.backend_subnet.id
  }

  metadata = {
    startup-script = local.backend_startup_script
    enable-oslogin = "TRUE"
  }

  service_account {
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# 2. Managed Instance Group (Zonal MIG - Size 2)
resource "google_compute_instance_group_manager" "backend_mig" {
  name               = "${var.name_prefix}-mig"
  base_instance_name = "${var.name_prefix}-vm"
  zone               = var.zone
  target_size        = var.mig_target_size
  description        = "Managed Instance Group serving SMG Security Demo behind Cloud Armor"

  version {
    name              = "primary"
    instance_template = google_compute_instance_template.backend_template.self_link
  }

  named_port {
    name = "http"
    port = 80
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.http_health_check.id
    initial_delay_sec = 120
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 1
    max_unavailable_fixed = 0
  }
}
