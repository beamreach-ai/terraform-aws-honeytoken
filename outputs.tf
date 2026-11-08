output "access_key_id" {
  description = "The decoy access key ID (AKIA...). Plant it together with the secret."
  value       = aws_iam_access_key.decoy.id
}

output "secret_access_key" {
  description = "The decoy secret access key. null when pgp_key is set; use encrypted_secret_access_key instead."
  value       = aws_iam_access_key.decoy.secret
  sensitive   = true
}

output "encrypted_secret_access_key" {
  description = "The secret access key encrypted with pgp_key, base64. null without pgp_key."
  value       = aws_iam_access_key.decoy.encrypted_secret
}

output "user_arn" {
  description = "ARN of the decoy IAM user."
  value       = aws_iam_user.decoy.arn
}

output "sns_topic_arn" {
  description = "Topic that receives the alerts."
  value       = local.topic_arn
}

output "home_region" {
  description = "Region that receives every alert (the provider's region)."
  value       = local.home_region
}

output "watched_regions" {
  description = "Regions with an EventBridge rule for the decoy key."
  value       = sort(tolist(local.watched_regions))
}
