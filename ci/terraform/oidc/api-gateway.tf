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
  name = "${var.environment}-api-gateway-logging-lambda-role"

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

resource "aws_iam_policy" "api_gateway_logging_policy" {
  name        = "${var.environment}-api-gateway-logging"
  path        = "/"
  description = "IAM policy for logging for API Gateway"

  policy = data.aws_iam_policy_document.api_gateway_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "api_gateway_logging_logs" {
  role       = aws_iam_role.api_gateway_logging_iam_role.name
  policy_arn = aws_iam_policy.api_gateway_logging_policy.arn
}

resource "aws_api_gateway_rest_api" "di_authentication_api" {
  name = "${var.environment}-di-authentication-api"

  tags = local.default_tags
}

resource "aws_api_gateway_usage_plan" "di_auth_usage_plan" {
  name = "${var.environment}-di-auth-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.di_authentication_api.id
    stage  = aws_api_gateway_stage.endpoint_stage.stage_name
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_stage,
    aws_api_gateway_rest_api.di_authentication_api,
  ]
}

resource "aws_api_gateway_api_key" "di_auth_api_key" {
  name = "${var.environment}-di-auth-api-key"
}

resource "aws_api_gateway_usage_plan_key" "di_auth_usage_plan_key" {
  key_id        = aws_api_gateway_api_key.di_auth_api_key.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.di_auth_usage_plan.id
}

resource "aws_api_gateway_resource" "wellknown_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = ".well-known"
}

resource "aws_api_gateway_resource" "connect_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "connect"
}

resource "aws_api_gateway_resource" "register_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_resource.connect_resource.id
  path_part   = "register"
}

data "aws_region" "current" {
}

locals {
  api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_authentication_api.id}/${var.environment}/_user_request_" : "https://api.${var.environment}.${var.service_domain_name}"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.auth-code.integration_trigger_value,
      module.auth-code.method_trigger_value,
      module.authorize.integration_trigger_value,
      module.authorize.method_trigger_value,
      module.jwks.integration_trigger_value,
      module.jwks.method_trigger_value,
      module.logout.integration_trigger_value,
      module.logout.method_trigger_value,
      module.openid_configuration_discovery.integration_trigger_value,
      module.openid_configuration_discovery.method_trigger_value,
      module.register.integration_trigger_value,
      module.register.method_trigger_value,
      module.reset_password.integration_trigger_value,
      module.reset_password.method_trigger_value,
      module.token.integration_trigger_value,
      module.token.method_trigger_value,
      module.trustmarks.integration_trigger_value,
      module.trustmarks.method_trigger_value,
      module.update.integration_trigger_value,
      module.update.method_trigger_value,
      module.userinfo.integration_trigger_value,
      module.userinfo.method_trigger_value,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.auth-code,
    module.authorize,
    module.jwks,
    module.logout,
    module.openid_configuration_discovery,
    module.register,
    module.token,
    module.trustmarks,
    module.update,
    module.userinfo,
  ]
}

resource "aws_cloudwatch_log_group" "oidc_stage_execution_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_authentication_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "oidc_api_execution_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${var.environment}-oidc-api-execution-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.oidc_stage_execution_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_cloudwatch_log_group" "oidc_stage_access_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "${var.environment}-oidc-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "oidc_access_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${var.environment}-oidc-api-access-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.oidc_stage_access_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_api_gateway_stage" "endpoint_stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name    = var.environment

  dynamic "access_log_settings" {
    for_each = var.use_localstack ? [] : aws_cloudwatch_log_group.oidc_stage_access_logs
    iterator = log_group
    content {
      destination_arn = log_group.value.arn
      format          = local.access_logging_template
    }
  }

  tags = local.default_tags

  depends_on = [
    module.auth-code,
    module.authorize,
    module.jwks,
    module.logout,
    module.openid_configuration_discovery,
    module.register,
    module.token,
    module.trustmarks,
    module.update,
    module.userinfo,
    aws_api_gateway_deployment.deployment,
  ]
}

resource "aws_api_gateway_account" "api_gateway_logging_role" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_iam_role.arn

}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name  = aws_api_gateway_stage.endpoint_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = false
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_stage
  ]
}

resource "aws_api_gateway_base_path_mapping" "api" {
  count = var.use_localstack ? 0 : 1

  api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name  = aws_api_gateway_stage.endpoint_stage.stage_name
  domain_name = "api.${var.environment}.${var.service_domain_name}"
}

module "dashboard" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_authentication_api.name
  use_localstack   = var.use_localstack
}

resource "aws_wafregional_rate_based_rule" "wafregional_max_request_rate_rule" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-waf-max-request-rate"
  metric_name = "${replace(var.environment, "-", "")}WafMaxRequestRate"

  rate_key   = "IP"
  rate_limit = "250"
}

resource "aws_wafregional_web_acl" "wafregional_web_acl" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-waf-web-acl"
  metric_name = "${replace(var.environment, "-", "")}WafMaxRequestRate"

  default_action {
    type = "ALLOW"
  }

  rule {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id  = aws_wafregional_rate_based_rule.wafregional_max_request_rate_rule[count.index].id
    type     = "RATE_BASED"
  }
}

resource "aws_wafregional_web_acl_association" "association" {
  count        = var.use_localstack ? 0 : 1
  resource_arn = aws_api_gateway_stage.endpoint_stage.arn
  web_acl_id   = aws_wafregional_web_acl.wafregional_web_acl[count.index].id

  depends_on = [
    aws_api_gateway_stage.endpoint_stage,
    aws_wafregional_web_acl.wafregional_web_acl
  ]
}
