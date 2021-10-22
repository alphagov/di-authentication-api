resource "aws_kms_key" "events_topic_encryption" {
  description = "alias/${var.environment}/events-encryption-key"

  policy = data.aws_iam_policy_document.events_topic_encryption_key_access.json
}

data "aws_iam_policy_document" "events_topic_encryption_key_access" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-events-topic-encryption-key-access"

  statement {
    principals {
      identifiers = ["sqs.amazonaws.com", "sns.amazonaws.com"]
      type        = "Service"
    }

    effect  = "Allow"
    sid     = "GrantServiceAccess"
    actions = ["kms:GenerateDataKey*", "kms:Decrypt"]
  }

  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    effect  = "Allow"
    sid     = "Enable IAM User Permissions"
    actions = ["kms:*"]
  }
}


resource "aws_sns_topic" "events" {
  name              = "${var.environment}-events"
  kms_master_key_id = "alias/aws/sns"
  tags              = local.default_tags
}

data "aws_iam_policy_document" "events_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-events-sns-topic-policy"

  statement {
    effect = "Allow"
    sid    = "GiveEventsSnsTopicPolicyPublish"
    actions = [
      "SNS:Publish",
      "SNS:RemovePermission",
      "SNS:SetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:Receive",
      "SNS:AddPermission",
      "SNS:Subscribe"
    ]
    resources = [aws_sns_topic.events.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowLambdasToEncryptWithCustomKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.events_topic_encryption.arn
    ]
  }
}

resource "aws_iam_policy" "lambda_sns_policy" {
  name        = "${var.environment}-standard-lambda-sns-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda"

  policy = data.aws_iam_policy_document.events_policy_document.json
}

resource "aws_iam_role_policy_attachment" "lambda_sns" {
  role       = local.lambda_iam_role_name
  policy_arn = aws_iam_policy.lambda_sns_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_sns_token" {
  role       = local.lambda_iam_role_name
  policy_arn = aws_iam_policy.lambda_sns_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_sns_sqs" {
  role       = local.sqs_lambda_iam_role_name
  policy_arn = aws_iam_policy.lambda_sns_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_sns_dynamo" {
  role       = local.dynamo_sqs_lambda_iam_role_name
  policy_arn = aws_iam_policy.lambda_sns_policy.arn
}
