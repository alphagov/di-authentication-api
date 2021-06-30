resource "aws_iam_role" "email_lambda_iam_role" {
  name = "${var.environment}-email-notification-sqs-lambda-role"

  assume_role_policy = var.lambda_iam_policy

  tags = {
    environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "emaiL_lambda_logging_policy" {
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn

  depends_on = [
    aws_iam_role.email_lambda_iam_role,
    aws_iam_policy.endpoint_logging_policy,
  ]
}

resource "aws_iam_role_policy_attachment" "emaiL_lambda_networking_policy" {
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn

  depends_on = [
    aws_iam_role.email_lambda_iam_role,
    aws_iam_policy.endpoint_networking_policy,
  ]
}

resource "aws_sqs_queue" "email_queue" {
  name                      = "${var.environment}-email-notification-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10

  tags = {
    environment = var.environment
  }
}

resource "time_sleep" "wait_60_seconds" {
  depends_on = [aws_sqs_queue.email_queue]
  count      = var.use_localstack ? 0 : 1

  create_duration = "60s"
}

data "aws_iam_policy_document" "email_queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.sqs_lambda_iam_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.email_queue.arn
    ]
  }

  statement {
    sid    = "ReceiveSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.email_lambda_iam_role.arn]
    }

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.email_queue.arn
    ]
  }

  depends_on = [
    time_sleep.wait_60_seconds,
    aws_iam_role.email_lambda_iam_role,
    aws_iam_role.sqs_lambda_iam_role,
  ]
}

resource "aws_sqs_queue_policy" "email_queue_policy" {
  depends_on = [
    time_sleep.wait_60_seconds,
    data.aws_iam_policy_document.email_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.email_queue.id
  policy    = data.aws_iam_policy_document.email_queue_policy_document.json
}

resource "aws_lambda_event_source_mapping" "lambda_sqs_mapping" {
  event_source_arn = aws_sqs_queue.email_queue.arn
  function_name    = aws_lambda_function.email_sqs_lambda.arn

  depends_on = [
    aws_sqs_queue.email_queue,
    aws_sqs_queue_policy.email_queue_policy,
    aws_lambda_function.email_sqs_lambda,
    aws_iam_role.lambda_iam_role,
  ]
}

resource "aws_lambda_function" "email_sqs_lambda" {
  filename      = var.lambda_zip_file
  function_name = "${var.environment}-email-notification-sqs-lambda"
  role          = aws_iam_role.email_lambda_iam_role.arn
  handler       = "uk.gov.di.lambdas.NotificationHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"

  source_code_hash = filebase64sha256(var.lambda_zip_file)
  vpc_config {
    security_group_ids = [aws_vpc.authentication.default_security_group_id]
    subnet_ids         = aws_subnet.authentication.*.id
  }
  environment {
    variables = {
      VERIFY_EMAIL_TEMPLATE_ID = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
      NOTIFY_API_KEY           = var.notify_api_key
      NOTIFY_URL               = var.notify_url
    }
  }

  tags = {
    environment = var.environment
  }

  depends_on = [
    aws_iam_role.lambda_iam_role,
  ]
}
