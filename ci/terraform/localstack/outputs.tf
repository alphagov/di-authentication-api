output "token_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/token"
}

output "authorise_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/authorize"
}

output "userinfo_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/userinfo"
}

output "openid_configuration_discovery_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/.well-known/openid-configuration"
}

output "jwks" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/.well-known/jwks.json"
}

output "signup" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/signup"
}

output "register" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/connect/register"
}

output "userexists_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/userexists"
}

output "send_notification_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/send-notification"
}

output "verify_code_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/verify-code"
}

output "api_gateway_root_id" {
  value = module.api_gateway_root.di_authentication_api_id
}