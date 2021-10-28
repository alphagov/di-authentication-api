environment                         = "local"
aws_endpoint                        = "http://localhost:45678"
aws_dynamodb_endpoint               = "http://localhost:8000"
use_localstack                      = true
redis_use_tls                       = "false"
external_redis_password             = "redis"
keep_lambdas_warm                   = false
dns_state_bucket                    = null
dns_state_key                       = null
dns_state_role                      = null
shared_state_bucket                 = "terraform-state"
test_client_verify_email_otp        = "123456"
test_client_verify_phone_number_otp = "123456"
test_clients_enabled                = "true"
client_registry_api_enabled         = true
terms_and_conditions                = "1.0"