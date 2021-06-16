module "userexists" {
  source = "../modules/endpoint-module"

  endpoint_name   = "user-exists"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    BASE_URL = var.api_base_url
    REDIS_HOST     = aws_elasticache_replication_group.sessions_store.primary_endpoint_address
    REDIS_PORT     = aws_elasticache_replication_group.sessions_store.port
    REDIS_PASSWORD = random_password.redis_password.result
    REDIS_TLS      = "true"
  }
  handler_function_name = "uk.gov.di.lambdas.CheckUserExistsHandler::handleRequest"

  rest_api_id               = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id          = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn             = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
  lambda_role_arn           = aws_iam_role.lambda_iam_role.arn

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
    aws_vpc.authentication,
    aws_subnet.authentication,
    aws_elasticache_replication_group.sessions_store,
  ]
}