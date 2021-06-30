variable "lambda_zip_file" {
  default     = "../../../serverless/lambda/build/distributions/lambda.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "notify_api_key" {
  description = "The API key required to communicate with Notify"
  type        = string
}

variable "notify_url" {
  type    = string
  default = null
}

variable "environment" {
  type    = string
  default = "test"
}

variable "api_deployment_stage_name" {
  type    = string
  default = "test"
}

variable "api_base_url" {
  type    = string
  default = "http://localhost:8080"
}

variable "lambda_iam_policy" {
  type    = string
  default = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "aws_dynamodb_endpoint" {
  type    = string
  default = null
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "external_redis_host" {
  type    = string
  default = "redis"
}

variable "external_redis_port" {
  type    = number
  default = 6379
}

variable "external_redis_password" {
  type    = string
  default = null
}

variable "redis_use_tls" {
  type    = string
  default = "true"
}
