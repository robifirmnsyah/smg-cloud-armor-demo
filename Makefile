# ==============================================================================
# PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
# Use Case: Cloud Armor Enterprise WAF + L7 DDoS Mitigation & OWASP Top 10 Drill
# File: Makefile
# ==============================================================================

PROJECT_ID  ?= dev-robifirmansyah
REGION      ?= asia-southeast2
ZONE        ?= asia-southeast2-a
NAME_PREFIX ?= smg-armor
MIG_NAME    ?= $(NAME_PREFIX)-mig
POLICY_NAME ?= $(NAME_PREFIX)-waf-policy

.PHONY: help init validate plan apply roll-backend attack-drill verify-logs status destroy

help:
	@echo "================================================================================"
	@echo " PT Smartnet Magna Global (SMG) | Google Cloud Premier Partner"
	@echo " SMG Cloud Armor Enterprise WAF + L7 DDoS & OWASP Top 10 Live Drill"
	@echo "================================================================================"
	@echo " Available Targets:"
	@echo "   make init          - Initialize Terraform & configure GCS state backend"
	@echo "   make plan          - Validate & preview Terraform execution plan"
	@echo "   make apply         - Provision VPC, Zero-IP MIG, Global ALB & Cloud Armor WAF"
	@echo "   make roll-backend  - Trigger zero-downtime rolling replacement on Backend MIG"
	@echo "   make attack-drill  - Execute 6-stage OWASP Top 10 & L7 DDoS live attack drill"
	@echo "   make verify-logs   - Audit real-time Cloud Armor security logs in Cloud Logging"
	@echo "   make destroy       - Tear down all demo infrastructure cleanly"
	@echo "================================================================================"

init:
	@echo "==> [SMG] Initializing Terraform with GCS Backend..."
	terraform init -upgrade

validate:
	@echo "==> [SMG] Validating Terraform HCL configuration..."
	terraform fmt -check
	terraform validate

plan:
	@echo "==> [SMG] Generating Terraform Infrastructure Plan..."
	terraform plan -var-file=terraform.tfvars

apply:
	@echo "==> [SMG] Deploying SMG Cloud Armor Enterprise WAF Architecture..."
	terraform apply -var-file=terraform.tfvars -auto-approve

roll-backend:
	@echo "==> [SMG] Triggering Zero-Downtime Rolling Replacement for MIG: $(MIG_NAME)..."
	gcloud compute instance-groups managed rolling-action replace $(MIG_NAME) \
		--zone=$(ZONE) \
		--project=$(PROJECT_ID) \
		--max-surge=1 \
		--max-unavailable=0

attack-drill:
	@echo "==> [SMG] Launching OWASP Top 10 & Layer 7 DDoS Live Attack Simulation..."
	python3 scripts/attack_drill.py

verify-logs:
	@echo "==> [SMG] Fetching Real-Time Google Cloud Armor Telemetry from Cloud Logging..."
	python3 scripts/verify_logs.py --project=$(PROJECT_ID) --policy=$(POLICY_NAME)

status:
	@echo "==> [SMG] Checking Backend Health & Security Policy Attachment..."
	@echo "Load Balancer Anycast IP : $$(terraform output -raw lb_external_ip 2>/dev/null || echo 'N/A')"
	@echo "Backend Service Name     : $$(terraform output -raw backend_service_name 2>/dev/null || echo 'N/A')"
	@echo "Cloud Armor WAF Policy   : $$(terraform output -raw security_policy_name 2>/dev/null || echo 'N/A')"
	gcloud compute backend-services get-health $(NAME_PREFIX)-backend-svc \
		--global \
		--project=$(PROJECT_ID) || true

destroy:
	@echo "==> [SMG] Destroying SMG Cloud Armor Demo Infrastructure..."
	terraform destroy -var-file=terraform.tfvars -auto-approve
