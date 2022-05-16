ipv_api_enabled                = false
ipv_capacity_allowed           = false
ipv_authorisation_client_id    = "authOrchestrator"
ipv_authorisation_uri          = "https://integration-di-ipv-core-front.london.cloudapps.digital/oauth2/authorize"
ipv_authorisation_callback_uri = "https://oidc.integration.account.gov.uk/ipv-callback"
ipv_backend_uri                = "https://18zwbqzm0k.execute-api.eu-west-2.amazonaws.com/integration"
ipv_sector                     = "https://identity.integration.account.gov.uk"
ipv_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzgTML6YZ+XUEPQprWBlW
oZ9FwasmRGsdLHLgAhyNWDw4PtYaihhpSOxoI+86IeO1qAe1nfqrFGW+X37jxDBz
clY/TxQkivEQqLCWmohuFcpn5dxz6SSC+WFhwLtedC8gXUv1JP4E0mgr7OKWh7t3
RQcpGyTaAGXh2wywZXytVOLDcwwPb0PeFiC8MR0A8tIpYyx1yXjKcs1Aga8Xy0HF
V9pU5gbB7a/XLl7j3CHePsfImYi4wG17y+jbN7+vF3GDpAqyRa78ctTZT9/WBWzP
cX8yiRmHf7ID9br2MsdrTO9YyVWfI0z7OZB1GnNe5lJhGBXvd3xg4UjWbnHikliE
NQIDAQAB
-----END PUBLIC KEY-----
EOT
logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prod",
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]