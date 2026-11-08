# One decoy key, alerts by email from every enabled region, plus the
# CloudTrail log-group backstop. The account needs a trail that records
# read and write management events (see the module README).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

# Home region: every alert ends up here. Keep it us-east-1, where calls to
# global endpoints are logged.
provider "aws" {
  region = "us-east-1"
}

variable "alert_email" {
  type = string
}

module "honeytoken" {
  source = "../.."

  user_name    = "svc-backup-reporting" # match your real naming style
  alert_emails = [var.alert_email]

  # Optional backstop. Remove if you have no trail writing to CloudWatch Logs.
  cloudtrail_log_group_name = "cloudtrail/management-events"
}

output "access_key_id" {
  value = module.honeytoken.access_key_id
}

output "secret_access_key" {
  value     = module.honeytoken.secret_access_key
  sensitive = true
}

output "watched_regions" {
  value = module.honeytoken.watched_regions
}
