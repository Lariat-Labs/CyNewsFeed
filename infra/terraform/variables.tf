variable "subscription_id" {
  description = "Azure subscription ID (az account show --query id -o tsv)"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus2"
}

variable "name" {
  description = "Base name for resources"
  type        = string
  default     = "cynews"
}

variable "tags" {
  type    = map(string)
  default = { app = "cynewsfeed" }
}

variable "image_tag" {
  description = "Container image tag in ACR (set by scripts/deploy.sh)"
  type        = string
  default     = "latest"
}

# ---------- AI ----------
variable "ai_provider" {
  description = "claude | azureopenai | ollama | none"
  type        = string
  default     = "claude"
}

variable "anthropic_api_key" {
  type      = string
  default   = ""
  sensitive = true
}

variable "claude_model" {
  description = "Model for per-item summaries/tags/rule scoring"
  type        = string
  default     = "claude-haiku-5-5"
}

variable "claude_digest_model" {
  description = "Model for the daily digest"
  type        = string
  default     = "claude-opus-5-5"
}

variable "claude_chat_model" {
  description = "Model for the interactive research agent"
  type        = string
  default     = "claude-opus-5-5"
}

# ---------- Threat-intel lookups for the agent (optional) ----------
variable "virustotal_api_key" {
  type      = string
  default   = ""
  sensitive = true
}

variable "abuseipdb_api_key" {
  type      = string
  default   = ""
  sensitive = true
}

variable "nvd_api_key" {
  description = "Optional; raises NVD rate limits"
  type        = string
  default     = ""
  sensitive   = true
}

variable "azure_openai_endpoint" {
  type    = string
  default = ""
}

variable "azure_openai_deployment" {
  type    = string
  default = ""
}

variable "azure_openai_api_key" {
  type      = string
  default   = ""
  sensitive = true
}

# ---------- Slack ----------
variable "slack_webhook_url" {
  type      = string
  default   = ""
  sensitive = true
}

# ---------- Schedule (Container Apps Job cron is evaluated in UTC) ----------
variable "fetch_cron_utc" {
  type    = string
  default = "0 * * * *"
}

variable "digest_cron_utc" {
  description = "Daily digest schedule in UTC. 14:00 UTC = 08:00 US Central (standard time)."
  type        = string
  default     = "0 14 * * *"
}

variable "timezone" {
  description = "Display/digest-date timezone"
  type        = string
  default     = "America/Chicago"
}

variable "retention_days" {
  type    = number
  default = 90
}

# ---------- Auth ----------
variable "enable_auth" {
  description = "Protect the app with Entra ID (Container Apps Easy Auth). Requires permission to create app registrations."
  type        = bool
  default     = true
}

# ---------- Integrations ----------
variable "misp_url" {
  description = "Optional MISP base URL for pushing IOCs"
  type        = string
  default     = ""
}

variable "misp_key" {
  type      = string
  default   = ""
  sensitive = true
}
