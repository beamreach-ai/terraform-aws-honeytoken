# An IAM access key that can do nothing, plus an alert on any API call made with it.
# Background and the AWS details behind each choice:
# https://beamreach.ai/docs/aws-canary-credentials.html

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

data "aws_regions" "enabled" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required", "opted-in"]
  }
}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  home_region   = data.aws_region.current.region
  resource_name = coalesce(var.resource_name, "${var.user_name}-activity")
  home_bus_arn  = "arn:${local.partition}:events:${local.home_region}:${local.account_id}:event-bus/default"

  watched_regions = toset(concat(
    [local.home_region],
    var.regions != null ? var.regions : tolist(data.aws_regions.enabled.names),
  ))
  forward_regions = setsubtract(local.watched_regions, [local.home_region])

  create_topic  = var.sns_topic_arn == null
  topic_arn     = local.create_topic ? aws_sns_topic.alerts[0].arn : var.sns_topic_arn
  with_backstop = var.cloudtrail_log_group_name != null

  # Matches every CloudTrail-recorded call made as the decoy user, allowed or denied.
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        arn = [aws_iam_user.decoy.arn]
      }
    }
  })
}

# --- The decoy user and key -------------------------------------------------

resource "aws_iam_user" "decoy" {
  name = var.user_name
  path = var.user_path
  # No login profile (no console password) and no tags: nothing that marks it as a decoy.
}

# An explicit deny wins over any allow, so the key stays useless even if someone
# attaches a policy to this user later. sts:GetCallerIdentity can't be denied and is logged.
resource "aws_iam_user_policy" "deny_all" {
  name = local.resource_name
  user = aws_iam_user.decoy.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_access_key" "decoy" {
  user    = aws_iam_user.decoy.name
  pgp_key = var.pgp_key
}

# --- Alert destination ------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  count = local.create_topic ? 1 : 0
  name  = local.resource_name
  tags  = var.tags
}

data "aws_iam_policy_document" "alerts" {
  count = local.create_topic ? 1 : 0

  statement {
    sid       = "EventBridgePublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts[0].arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:events:${local.home_region}:${local.account_id}:rule/*"]
    }
  }

  statement {
    sid       = "CloudWatchAlarmPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts[0].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudwatch:${local.home_region}:${local.account_id}:alarm:*"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  count  = local.create_topic ? 1 : 0
  arn    = aws_sns_topic.alerts[0].arn
  policy = data.aws_iam_policy_document.alerts[0].json
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = local.create_topic ? toset(var.alert_emails) : toset([])
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# --- Fast path: EventBridge -------------------------------------------------
# A rule in the plain ENABLED state ignores read-only calls such as
# GetCallerIdentity, usually the attacker's first call. Every rule here,
# including the forwarding ones, needs ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS.

resource "aws_cloudwatch_event_rule" "home" {
  name          = local.resource_name
  description   = "Calls made with the ${var.user_name} access key"
  state         = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
  event_pattern = local.event_pattern
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "home" {
  rule = aws_cloudwatch_event_rule.home.name
  arn  = local.topic_arn
}

# Events land in the region that was called. Rules in every other region
# forward matches to the home region's default bus, where the rule above sends them on.

resource "aws_iam_role" "forwarder" {
  count = length(local.forward_regions) > 0 ? 1 : 0
  name  = "${local.resource_name}-forwarder"
  tags  = var.tags
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "forwarder" {
  count = length(local.forward_regions) > 0 ? 1 : 0
  name  = "put-events-home-bus"
  role  = aws_iam_role.forwarder[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = local.home_bus_arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "forward" {
  for_each      = local.forward_regions
  region        = each.key
  name          = local.resource_name
  description   = "Forward calls made with the ${var.user_name} access key to ${local.home_region}"
  state         = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
  event_pattern = local.event_pattern
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "forward" {
  for_each = local.forward_regions
  region   = each.key
  rule     = aws_cloudwatch_event_rule.forward[each.key].name
  arn      = local.home_bus_arn
  role_arn = aws_iam_role.forwarder[0].arn
}

# --- Backstop: trail -> CloudWatch Logs -> metric filter -> alarm ------------
# Slower (CloudTrail log delivery averages about 5 minutes) and it pages once
# per transition to ALARM, but it covers every region the trail covers.

resource "aws_cloudwatch_log_metric_filter" "backstop" {
  count          = local.with_backstop ? 1 : 0
  name           = local.resource_name
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{ $.userIdentity.arn = \"${aws_iam_user.decoy.arn}\" }"

  metric_transformation {
    name      = local.resource_name
    namespace = var.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "backstop" {
  count               = local.with_backstop ? 1 : 0
  alarm_name          = local.resource_name
  alarm_description   = "Calls made with the ${var.user_name} access key, from the CloudTrail log group"
  namespace           = var.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.backstop[0].metric_transformation[0].name
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.topic_arn]
  tags                = var.tags
}
