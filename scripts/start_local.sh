#!/bin/sh

# export LOGGING_LEVEL='INFO' # {DEBUG | INFO(default) | ERROR | CRITICAL}
# export SKIP_TLS_VERIFY='false'
# export VAULT_REQUEST_TIMEOUT=20
# export VAULT_REQUEST_RETRY_COUNT=5
# export IBM_CLOUD_IAM_URL='https://iam.cloud.ibm.com/identity/token'
# export AZURE_IAM_URL='https://login.microsoftonline.com'
export GIT_REPO_URL='https://github.ibm.com/PrivateCloud-analytics/zen-vault-bridge-sdk'
export ERROR_DOC_PATH='/blob/main/docs/apidoc/error_codes.md'


export TLS_CERTITICATE_FILE_PATH="../certs/key.pem"
export TLS_KEY_FILE_PATH="../certs/cert.pem"
export JWT_PUBLIC_KEY_PATH="../certs/jwt/public.pem"

cd ./vault_sdk
source env/bin/activate
gunicorn --keyfile ${TLS_KEY_FILE_PATH} --certfile ${TLS_CERTITICATE_FILE_PATH}  --bind 0.0.0.0:8443 wsgi:app
cd ../