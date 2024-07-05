.PHONY: all .venv clean install api delete request
# Makefile to call the script with parameters extracted from terraform output

# Extracting values from terraform output
TF_OUTPUT := $(shell terraform -chdir=infrastructure output -json)
API_GATEWAY_URL := $(shell echo '$(TF_OUTPUT)' | jq -r '.api_gateway_url.value')
COGNITO_RESOURCE_SERVER_IDENTIFIER := $(shell echo '$(TF_OUTPUT)' | jq -r '.cognito_resource_server_identifier.value')
COGNITO_USER_POOL_CLIENT_ALLOWED_OAUTH_SCOPES := $(shell echo '$(TF_OUTPUT)' | jq -r '.cognito_user_pool_client_allowed_oauth_scopes.value | join(" ")')
COGNITO_USER_POOL_CLIENT_CALLBACK_URLS := $(shell echo '$(TF_OUTPUT)' | jq -r '.cognito_user_pool_client_callback_urls.value[0]')
COGNITO_USER_POOL_CLIENT_ID := $(shell echo '$(TF_OUTPUT)' | jq -r '.cognito_user_pool_client_id.value')
COGNITO_USER_POOL_DOMAIN_URL := $(shell echo '$(TF_OUTPUT)' | jq -r '.cognito_user_pool_domain_url.value')
USER_POOL_ID := $(shell echo '$(TF_OUTPUT)' | jq -r '.cognito_user_pool_id.value')
REGION := $(shell echo '$(COGNITO_USER_POOL_DOMAIN_URL)' | cut -f 3 -d '.')
USER_POOL_JWT_ISSUER_URL := $(shell echo "https://cognito-idp.$(REGION).amazonaws.com/$(USER_POOL_ID)")


all: .env .venv install api

# Define the command to run the script
request:
	source .env && source .venv/bin/activate && \
	python3 tokens.py \
		--scopes "$(COGNITO_USER_POOL_CLIENT_ALLOWED_OAUTH_SCOPES)" \
		--callback-url "$(COGNITO_USER_POOL_CLIENT_CALLBACK_URLS)" \
		--client-id "$(COGNITO_USER_POOL_CLIENT_ID)" \
		--token-url "$(COGNITO_USER_POOL_DOMAIN_URL)/oauth2/token" \
		--user-pool-auth-domain "$(COGNITO_USER_POOL_DOMAIN_URL)" \
		--user-pool-jwt-issuer-url "$(USER_POOL_JWT_ISSUER_URL)" \
		--api-url "$(API_GATEWAY_URL)"

api: .env
	source .env && terraform -chdir=infrastructure init && terraform -chdir=infrastructure plan -out tfplan && terraform -chdir=infrastructure apply tfplan

destroy:
	source .env && terraform -chdir=infrastructure destroy -auto-approve

.env:
	@read -p "Enter AWS_DEFAULT_REGION (e.g. us-east-1, eu-central-1): " AWS_DEFAULT_REGION; \
	read -p "Enter AWS_PROFILE (as defined in your .aws/config): " AWS_PROFILE; \
	echo 'export AWS_DEFAULT_REGION="'$$AWS_DEFAULT_REGION'"' > .env; \
	echo 'export AWS_PROFILE="'$$AWS_PROFILE'"' >> .env; \
	echo 'export TF_VAR_region="'$$AWS_DEFAULT_REGION'"' >> .env; \
	echo 'export TF_VAR_user_password="'"$$(openssl rand -base64 10)"'"' >> .env; \
	echo 'export TF_VAR_user_pool_domain_prefix="'"$$(tr -dc 'a-z' </dev/urandom | head -c 16)"'"' >> .env; \
	echo ".env file created."

.venv:
	python3 -m venv .venv
	source .venv/bin/activate && pip install --upgrade pip
	@echo "Virtual environment (.venv) created."
	@echo "Activating virtual environment (.venv)..."
	@echo "Run 'source .venv/bin/activate' to activate it."
	@echo "Then run 'make install' to install dependencies."

requirements.txt: requirements.in .venv
	source .venv/bin/activate && pip install pip-tools && pip-compile --strip-extras --output-file=requirements.txt requirements.in

install: .venv requirements.txt
	source .venv/bin/activate && pip install -r requirements.txt
	@echo "Python environment successfully set up"
	@echo "Run 'source .venv/bin/activate' to activate it."

clean:
	-rm requirements.txt
	-rm .env
	-rm -rf .venv 2>/dev/null
	-rm -rf __pycache__ 2>/dev/null
	@echo "Virtual environment removed."