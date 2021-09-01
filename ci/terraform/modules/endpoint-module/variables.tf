variable "endpoint_name" {
  type = string
}

variable "path_part" {
  type = string
}

variable "use_authorizer" {
  type = bool
  default = false
}

variable "method_request_parameters" {
  type = map(bool)
  default = {}
}

variable "integration_request_parameters" {
  type = map(string)
  default = {}
}

variable "endpoint_method" {
  type = string
}

variable "lambda_zip_file" {
  type = string
}

variable "handler_function_name" {
  type = string
}

variable "handler_environment_variables" {
  type = map(string)
}

variable "handler_runtime" {
  type    = string
  default = "java11"
}

variable "rest_api_id" {
  type = string
}

variable "root_resource_id" {
  type = string
}

variable "execution_arn" {
  type = string
}

variable "environment" {
  type    = string
}

variable "api_deployment_stage_name" {
  type    = string
  default = "test"
}

variable "security_group_id" {
  type = string
  description = "The id of the security for the lambda"
}

variable "subnet_id" {
  type = list(string)
  description = "The id of the subnets for the lambda"
}

variable "lambda_role_arn" {
  type = string
}

variable "api_gateway_role" {
  type = string
  default = ""
}

variable "logging_endpoint_enabled" {
  type        = bool
  default     = false
  description = "Whether the Lambda should ship its logs to the `logging_endpoint_arn`"
}

variable "logging_endpoint_arn" {
  type        = string
  default     = ""
  description = "Amazon Resource Name (ARN) for the endpoint to ship logs to"
}

variable "use_localstack" {
  type    = bool
}

variable "default_tags" {
  default     = {}
  type        = map(string)
  description = "Default tags to apply to all resources"
}