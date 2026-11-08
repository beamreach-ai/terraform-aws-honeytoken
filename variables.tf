variable "user_name" {
  description = "Name of the decoy IAM user. Make it look like your real service users (for example svc-backup-reporting). Anyone holding the key can learn this name with sts:GetCallerIdentity."
  type        = string

  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.user_name))
    error_message = "user_name must be a valid IAM user name: up to 64 characters from letters, digits and +=,.@_-."
  }

  validation {
    condition     = !can(regex("(?i)(canary|honey|decoy|trap|bait|fake)", var.user_name))
    error_message = "user_name gives the decoy away. An attacker sees it with sts:GetCallerIdentity, so name it like a real service user."
  }
}

variable "user_path" {
  description = "IAM path for the decoy user."
  type        = string
  default     = "/"
}

variable "resource_name" {
  description = "Base name for the supporting resources (EventBridge rules, forwarding role, SNS topic, metric filter, alarm). Defaults to \"<user_name>-activity\"."
  type        = string
  default     = null
}

variable "regions" {
  description = "Regions to watch. The provider's region is always included, because calls to global endpoints are logged in us-east-1 and forwarded events land in the home region. null watches every region enabled in the account, which is what you want unless an SCP blocks some of them."
  type        = list(string)
  default     = null
}

variable "sns_topic_arn" {
  description = "Existing SNS topic for alerts. It must be in the provider's region and must allow events.amazonaws.com (and cloudwatch.amazonaws.com, if you set cloudtrail_log_group_name) to publish. null creates a topic."
  type        = string
  default     = null
}

variable "alert_emails" {
  description = "Email addresses to subscribe to the created topic. Each one must click the confirmation link AWS sends. Ignored when sns_topic_arn is set."
  type        = list(string)
  default     = []
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch Logs group, in the provider's region, that a multi-region CloudTrail trail writes to. When set, a metric filter and alarm act as a slower backstop that also catches regions without a rule. null skips the backstop."
  type        = string
  default     = null
}

variable "metric_namespace" {
  description = "CloudWatch namespace for the backstop metric."
  type        = string
  default     = "Ops"
}

variable "pgp_key" {
  description = "Optional PGP key (base64 public key, or keybase:username) to encrypt the secret access key. Without it the secret is stored in Terraform state in plain text."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for the supporting resources. The decoy user itself is never tagged, so tags can't give it away."
  type        = map(string)
  default     = {}
}
