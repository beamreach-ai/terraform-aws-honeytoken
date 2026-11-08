# terraform-aws-honeytoken

A Terraform module for an AWS canary credential: a real IAM access key that
can do nothing, and an alert the moment anyone uses it.

You plant the key where an attacker looks for credentials: a CI variable, a
`.env` file, a config repo, a laptop's `~/.aws/credentials`. Nobody legitimate
ever uses it, so any call made with it means someone took it from that place.
There's no baseline to tune and very little doubt about the alert.

The design, and the AWS behaviours each part depends on, are explained step
by step in the guide
[AWS canary credentials: how to set up an IAM honeytoken](https://beamreach.ai/docs/aws-canary-credentials.html).
This module packages that guide's Terraform.

> **Status: 0.1, not yet applied to a real AWS account.** The tests run
> against a mocked provider, and AWS provider 6.72 validates the
> configuration. Run the [test](#test-it) after you apply it, and please
> open an issue with what you find.

## What it creates

- **The decoy:** an IAM user with no console password, no tags and an
  explicit deny on every action, and one access key. An explicit deny beats
  any allow, so the key stays useless even if someone attaches a policy later.
- **The fast path:** an EventBridge rule in the provider's region that sends
  every CloudTrail event from that user to SNS, plus a rule in **every other
  enabled region** that forwards matches to it. Every rule uses
  `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`. Without that state,
  EventBridge ignores read-only calls such as `sts:GetCallerIdentity`, which
  is usually the attacker's first call.
- **The alert topic:** an SNS topic with email subscriptions, or your
  existing topic.
- **An optional backstop:** a metric filter and alarm on your CloudTrail
  log group. It's slower, but it covers every region the trail covers.

## Usage

```hcl
provider "aws" {
  region = "us-east-1" # every alert arrives here
}

module "honeytoken" {
  source = "github.com/beamreach-ai/terraform-aws-honeytoken"

  user_name    = "svc-backup-reporting" # look like your real service users
  alert_emails = ["oncall@example.com"]
}
```

Then plant the output where you want to know about theft:

```sh
terraform output -raw access_key_id
terraform output -raw secret_access_key
```

Plant one key per location, so the key ID tells you which place was read.
For several locations, use the module once per location with a different
`user_name`.

### Requirements

- **AWS provider 6.0 or later.** The module places one rule per region
  through the provider's per-resource `region` argument.
- **A CloudTrail trail that logs management events, with `read_write_type`
  set to `All`.** EventBridge receives CloudTrail events only while a trail
  is logging. Event history alone isn't enough. Step 2b of the guide builds
  one.
- **Home region `us-east-1`, unless you have a reason to change it.** Calls
  to global endpoints such as the global STS endpoint are logged in
  us-east-1, and every alert is delivered in the provider's region.

## Inputs

| Name | Description | Default |
|---|---|---|
| `user_name` | Decoy IAM user name. Anyone holding the key can see it with `sts:GetCallerIdentity`, so names containing canary, honey, decoy, trap, bait or fake are rejected. | required |
| `user_path` | IAM path for the user. | `"/"` |
| `resource_name` | Base name for the rules, role, topic and alarm. | `"<user_name>-activity"` |
| `regions` | Regions to watch. The provider's region is always included. | every enabled region |
| `sns_topic_arn` | Existing topic in the provider's region. It must allow `events.amazonaws.com` to publish, and `cloudwatch.amazonaws.com` too if you use the backstop. | creates one |
| `alert_emails` | Emails to subscribe to the created topic. Each one must confirm. | `[]` |
| `cloudtrail_log_group_name` | Your trail's log group in the provider's region. Setting it turns on the backstop. | `null` |
| `metric_namespace` | Namespace for the backstop metric. | `"Ops"` |
| `pgp_key` | Encrypts the secret in state. | `null` |
| `tags` | Tags for supporting resources. The decoy user is never tagged. | `{}` |

## Outputs

| Name | Description |
|---|---|
| `access_key_id` | The decoy key ID. |
| `secret_access_key` | The secret (sensitive). `null` when `pgp_key` is set. |
| `encrypted_secret_access_key` | The secret encrypted with `pgp_key`, base64. |
| `user_arn` | ARN of the decoy user. |
| `sns_topic_arn` | Topic that receives the alerts. |
| `home_region` | Region where every alert arrives. |
| `watched_regions` | Regions with a rule. |

## Test it

Tell whoever is on call first. Then, from the directory where you applied the
module:

```sh
(
  export AWS_ACCESS_KEY_ID="$(terraform output -raw access_key_id)"
  export AWS_SECRET_ACCESS_KEY="$(terraform output -raw secret_access_key)"
  unset AWS_SESSION_TOKEN AWS_PROFILE
  date -u +%H:%M:%S
  aws sts get-caller-identity --region us-east-1   # read-only: succeeds, still alerts
  aws s3api list-buckets --region us-east-1        # denied: fails, still alerts
  aws sts get-caller-identity --region eu-west-1 \
    --endpoint-url https://sts.eu-west-1.amazonaws.com   # another region
)
```

You should get three alerts. Compare when each one arrives with the event's
`eventTime`: that's your latency. AWS doesn't publish a figure for the
EventBridge path, so measure your own. If the first call produces nothing,
check your trail. If only the third is missing, that region has no rule.

Repeat the test after changing regions, trails or alert routing. A canary
that silently stopped alerting is worse than none.

## When it trips

Read the event (`eventName`, `sourceIPAddress`, `userAgent`, `awsRegion`) and
rule out your own test. Then go to where that key was planted: whatever could
read the canary could also read the real credentials next to it. Contain and
rotate there. Leave the canary key active for now: it can't do anything, and
it shows you what the attacker tries next. Afterwards, destroy it and plant a
fresh one. The guide's section 12 covers the response in more detail.

## Limits

- **The account is visible.** Anyone holding a key ID can find out which
  account owns it without touching your logs. Choose the account the decoy
  lives in deliberately (guide, section 7).
- **The secret is stored in state.** It sits in Terraform state in plain
  text unless you set `pgp_key`. Anyone who steals it from state trips it.
- **The topic is unencrypted.** EventBridge can't publish to a topic
  encrypted with the AWS-managed SNS key. If you need encryption, pass your
  own topic with a customer-managed key whose policy lets EventBridge use it.
- **Some calls may not be logged.** Researchers have found AWS API calls
  that CloudTrail didn't record and that revealed the caller. A canary makes
  detection very likely, not guaranteed.
- **Organization trails haven't been checked.** We haven't confirmed where
  an organization trail's member-account events reach EventBridge. Apply the
  module in the account that owns the key, and test-fire it.

## Development

```sh
terraform init -backend=false && terraform test
```

The tests run against a mocked AWS provider. They need Terraform 1.7 or
later, but no credentials.

## About

Maintained by [Beamreach](https://beamreach.ai). [Compass](https://github.com/beamreach-ai/compass),
our open-source tool, plants decoys like this one as Terraform pull requests
based on a map of your account. You don't need Compass to use this module.

Licence: [Apache-2.0](LICENSE).
