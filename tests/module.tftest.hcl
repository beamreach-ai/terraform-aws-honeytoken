# Tests against a mocked AWS provider: "apply" here only applies to the mock. No credentials or AWS calls.
# Run: terraform init && terraform test   (Terraform 1.7 or later)

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }
  mock_data "aws_regions" {
    defaults = { names = ["us-east-1", "us-west-2", "eu-west-1"] }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_iam_user" {
    defaults = { arn = "arn:aws:iam::111122223333:user/svc-backup-reporting" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:111122223333:svc-backup-reporting-activity" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/svc-backup-reporting-activity-forwarder" }
  }
}

variables {
  user_name = "svc-backup-reporting"
}

run "defaults_watch_every_enabled_region" {
  command = apply

  assert {
    condition     = output.watched_regions == tolist(["eu-west-1", "us-east-1", "us-west-2"])
    error_message = "Expected every enabled region to be watched."
  }
  assert {
    condition     = length(aws_cloudwatch_event_rule.forward) == 2 && !contains(keys(aws_cloudwatch_event_rule.forward), "us-east-1")
    error_message = "Expected a forwarding rule in each non-home region and none in the home region."
  }
  assert {
    condition     = alltrue([for r in aws_cloudwatch_event_rule.forward : r.region != "us-east-1"])
    error_message = "Forwarding rules must be placed in their own region."
  }
  assert {
    condition     = aws_cloudwatch_event_target.forward["eu-west-1"].arn == "arn:aws:events:us-east-1:111122223333:event-bus/default"
    error_message = "Forwarding targets must point at the home region's default bus."
  }
  assert {
    condition     = length(aws_sns_topic.alerts) == 1 && length(aws_cloudwatch_log_metric_filter.backstop) == 0
    error_message = "Expected a created topic and no backstop by default."
  }
}

run "every_rule_matches_read_only_calls" {
  command = apply

  assert {
    condition = aws_cloudwatch_event_rule.home.state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" && alltrue([
      for r in aws_cloudwatch_event_rule.forward : r.state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    ])
    error_message = "Every rule needs ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS or GetCallerIdentity is missed."
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.home.event_pattern).detail.userIdentity.arn == ["arn:aws:iam::111122223333:user/svc-backup-reporting"]
    error_message = "The rule must match the decoy user's ARN."
  }
}

run "key_is_denied_everything" {
  command = apply

  assert {
    condition     = jsondecode(aws_iam_user_policy.deny_all.policy).Statement == [{ Effect = "Deny", Action = "*", Resource = "*" }]
    error_message = "The decoy user must carry an explicit deny on everything."
  }
  assert {
    condition     = length(aws_iam_user.decoy.tags == null ? {} : aws_iam_user.decoy.tags) == 0
    error_message = "The decoy user must not be tagged."
  }
}

run "explicit_regions_and_existing_topic" {
  command = apply

  variables {
    regions       = ["eu-west-1"]
    sns_topic_arn = "arn:aws:sns:us-east-1:111122223333:existing"
    alert_emails  = ["oncall@example.com"]
  }

  assert {
    condition     = output.watched_regions == tolist(["eu-west-1", "us-east-1"])
    error_message = "The home region must always be watched."
  }
  assert {
    condition     = length(aws_sns_topic.alerts) == 0 && length(aws_sns_topic_subscription.email) == 0
    error_message = "No topic or subscription when an existing topic is given."
  }
  assert {
    condition     = aws_cloudwatch_event_target.home.arn == "arn:aws:sns:us-east-1:111122223333:existing"
    error_message = "The home rule must target the existing topic."
  }
}

run "home_region_only_needs_no_forwarder" {
  command = apply

  variables {
    regions = ["us-east-1"]
  }

  assert {
    condition     = length(aws_iam_role.forwarder) == 0 && length(aws_cloudwatch_event_rule.forward) == 0
    error_message = "No forwarding role or rules when only the home region is watched."
  }
}

run "backstop_when_log_group_given" {
  command = apply

  variables {
    cloudtrail_log_group_name = "cloudtrail/management-events"
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.backstop[0].pattern == "{ $.userIdentity.arn = \"arn:aws:iam::111122223333:user/svc-backup-reporting\" }"
    error_message = "The metric filter must match the decoy user's ARN."
  }
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.backstop) == 1
    error_message = "Expected the backstop alarm."
  }
}

run "rejects_names_that_give_it_away" {
  command = plan

  variables {
    user_name = "aws-canary-key"
  }

  expect_failures = [var.user_name]
}
