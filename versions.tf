terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.0 added the per-resource `region` argument, which lets one provider
      # place a forwarding rule in every region.
      version = ">= 6.0"
    }
  }
}
