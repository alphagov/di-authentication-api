variable "lambda-zip-file" {
  default     = "../../../serverless/lambda/build/distributions/lambda.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}
variable "deployer-role-arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "environment" {
  type = string
  default = "local"
}

variable "api_deployment_stage_name" {
  type = string
  default = "local"
}

variable "api_base_url" {
  type = string
  default = "http://localhost:8080"
}