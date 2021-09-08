data "aws_iam_policy_document" "api_gateway_can_assume_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "apigateway.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "api_gateway_logging_iam_role" {
  name = "${var.environment}-account-management-api-gateway-logging-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json

  tags = local.default_tags
}

data "aws_iam_policy_document" "api_gateway_logging_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

resource "aws_api_gateway_authorizer" "di_account_management_api" {
  name                   = "${var.environment}-authorise-access-token"
  rest_api_id            = aws_api_gateway_rest_api.di_account_management_api.id
  authorizer_uri         = aws_lambda_function.authorizer.invoke_arn
  authorizer_credentials = aws_iam_role.invocation_role.arn
  authorizer_result_ttl_in_seconds = 0
}

resource "aws_iam_role_policy" "invocation_policy" {
  name = "default"
  role = aws_iam_role.invocation_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "lambda:InvokeFunction",
      "Effect": "Allow",
      "Resource": "${aws_lambda_function.authorizer.arn}"
    }
  ]
}
EOF
}

resource "aws_lambda_function" "authorizer" {
  filename      = var.lambda_zip_file
  function_name = "${var.environment}-api_gateway_authorizer"
  role          = aws_iam_role.lambda_iam_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler::handleRequest"
  runtime       = "java11"
  source_code_hash = filebase64sha256(var.lambda_zip_file)
  publish       = true
  timeout       = 30
  memory_size   = 2048
  vpc_config {
    security_group_ids = [aws_vpc.account_management_vpc.default_security_group_id]
    subnet_ids         = aws_subnet.account_management_subnets.*.id
  }
  environment {
    variables = {
      TOKEN_SIGNING_KEY_ID = data.aws_kms_key.id_token_public_key.key_id
    }
  }
}

resource "aws_iam_role" "invocation_role" {
  name = "${var.environment}-api_gateway_auth_invocation"
  path = "/"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json
}

resource "aws_iam_policy" "api_gateway_logging_policy" {
  name        = "${var.environment}-account-management-api-gateway-logging"
  path        = "/"
  description = "IAM policy for logging for API Gateway"

  policy = data.aws_iam_policy_document.api_gateway_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "api_gateway_logging_logs" {
  role       = aws_iam_role.api_gateway_logging_iam_role.name
  policy_arn = aws_iam_policy.api_gateway_logging_policy.arn
}

resource "aws_api_gateway_rest_api" "di_account_management_api" {
  name = "${var.environment}-di-account-management-api"

  tags = local.default_tags
}

data "aws_region" "current" {
}

locals {
  api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_account_management_api.id}/${var.environment}/_user_request_" : "https://api.${var.environment}.${var.service_domain_name}"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_account_management_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.update_email.integration_trigger_value,
      module.authenticate.integration_trigger_value,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.update_email,
    module.authenticate,
  ]
}

resource "aws_api_gateway_stage" "stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name    = var.environment

  tags = local.default_tags

  depends_on = [
    module.update_email,
    module.authenticate,
    aws_api_gateway_deployment.deployment,
  ]
}

resource "aws_api_gateway_account" "api_gateway_logging_role" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_iam_role.arn
}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {

  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = var.environment
  method_path = "*/*"

  settings {
    metrics_enabled    = false
    data_trace_enabled = true
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.stage
  ]
}

resource "aws_api_gateway_base_path_mapping" "api" {
  count = var.use_localstack ? 0 : 1

  api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  domain_name = "acct-mgmt-api.${var.environment}.${var.service_domain_name}"
}

module "dashboard" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_account_management_api.name
  use_localstack   = var.use_localstack
}