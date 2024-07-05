variable "user_password" {
  type = string
}

variable "user_pool_domain_prefix" {
  type = string
}

variable "region" {
  type = string
}

provider "aws" {
  region = var.region
}


# Cognito User Pool
resource "aws_cognito_user_pool" "example" {
  name = "example-user-pool"

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  #admin_create_user_config {
  #  allow_admin_create_user_only = true
  #}

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  lifecycle {
    ignore_changes = [
      schema, # Ignore changes to the schema attribute
    ]
  }
}

# Cognito User Pool Client
resource "aws_cognito_user_pool_client" "terminal_app_client" {
  name                                 = "terminal-app-client"
  user_pool_id                         = aws_cognito_user_pool.example.id
  generate_secret                      = false
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "${aws_api_gateway_rest_api.api.execution_arn}/read:HelloWorld"]
  allowed_oauth_flows_user_pool_client = true
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["http://localhost:8083/callback"]
}

# Cognito User Pool Domain
resource "aws_cognito_user_pool_domain" "example" {
  domain       = var.user_pool_domain_prefix # random domain prefix
  user_pool_id = aws_cognito_user_pool.example.id
}

# Cognito Resource Server
resource "aws_cognito_resource_server" "example" {
  user_pool_id = aws_cognito_user_pool.example.id
  identifier   = aws_api_gateway_rest_api.api.execution_arn
  name         = "Example Resource Server"

  scope {
    scope_name        = "read:HelloWorld"
    scope_description = "Read Hello World messages"
  }
}

# Create a test user in Cognito User Pool
resource "aws_cognito_user" "test_user" {
  user_pool_id = aws_cognito_user_pool.example.id
  username     = "testuser@example.com"

  attributes = {
    email          = "testuser@example.com"
    email_verified = true
  }

  password = var.user_password
}

# Create an API Gateway REST API
resource "aws_api_gateway_rest_api" "api" {
  name        = "hello-world-api"
  description = "API to say hello"
}

# Create a Cognito User Pool Authorizer
resource "aws_api_gateway_authorizer" "cognito_authorizer" {
  name                             = "CognitoAuthorizer"
  rest_api_id                      = aws_api_gateway_rest_api.api.id
  identity_source                  = "method.request.header.Authorization"
  type                             = "COGNITO_USER_POOLS"
  provider_arns                    = [aws_cognito_user_pool.example.arn]
  authorizer_result_ttl_in_seconds = 300
}

# Create the /hello resource
resource "aws_api_gateway_resource" "hello_resource" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "hello"
}

# Create a GET method for the /hello resource
resource "aws_api_gateway_method" "hello_get" {
  rest_api_id          = aws_api_gateway_rest_api.api.id
  resource_id          = aws_api_gateway_resource.hello_resource.id
  http_method          = "GET"
  authorization        = "COGNITO_USER_POOLS"
  authorizer_id        = aws_api_gateway_authorizer.cognito_authorizer.id
  authorization_scopes = ["${aws_api_gateway_rest_api.api.execution_arn}/read:HelloWorld"]
  api_key_required     = false
}

# Define a mock integration for the /hello GET method
resource "aws_api_gateway_integration" "hello_get" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.hello_resource.id
  http_method = aws_api_gateway_method.hello_get.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

# Create a method response for the /hello GET method
resource "aws_api_gateway_method_response" "hello_get_200" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.hello_resource.id
  http_method = aws_api_gateway_method.hello_get.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }
}

# Create an integration response for the /hello GET method
resource "aws_api_gateway_integration_response" "hello_get_200" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.hello_resource.id
  http_method = aws_api_gateway_method.hello_get.http_method
  status_code = aws_api_gateway_method_response.hello_get_200.status_code

  response_templates = {
    "application/json" = "{\"message\": \"hello world\"}"
  }
}

# Deploy the API
resource "aws_api_gateway_deployment" "api_deployment" {
  depends_on = [
    aws_api_gateway_integration.hello_get,
    aws_api_gateway_method_response.hello_get_200,
    aws_api_gateway_integration_response.hello_get_200
  ]

  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = "prod"
}

output "cognito_user_pool_domain_url" {
  value = "https://${aws_cognito_user_pool_domain.example.domain}.auth.us-east-1.amazoncognito.com"
}

output "cognito_user_pool_client_id" {
  value = aws_cognito_user_pool_client.terminal_app_client.id
}

output "cognito_user_pool_client_callback_urls" {
  value = aws_cognito_user_pool_client.terminal_app_client.callback_urls
}

output "cognito_user_pool_client_allowed_oauth_scopes" {
  value = aws_cognito_user_pool_client.terminal_app_client.allowed_oauth_scopes
}

output "cognito_resource_server_identifier" {
  value = aws_cognito_resource_server.example.identifier
}

output "api_gateway_url" {
  value = "${aws_api_gateway_deployment.api_deployment.invoke_url}/hello"
}
output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.example.id
}

output "user_password" {
  value = var.user_password
}
