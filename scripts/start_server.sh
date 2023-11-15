#!/bin/sh

cert_path="--certfile /certs/cert.pem"
key_path="--keyfile /certs/key.pem"

# For standalone server in airgap enviroment override the following with on-prem git repository
# export GIT_REPO_URL='https://github.com/IBM/zen-secrets-vaults'
# export ERROR_DOC_PATH='/blob/main/docs/apidoc/error_codes.md'

if [ ! -z "$TLS_CERTITICATE_FILE_PATH" ] && [ ! -z "$TLS_KEY_FILE_PATH" ]; then
    cert_path="--certfile $TLS_CERTITICATE_FILE_PATH"
    key_path="--keyfile $TLS_KEY_FILE_PATH"
fi

cd ./vault_sdk 
gunicorn $key_path $cert_path --bind 0.0.0.0:8443 wsgi:app