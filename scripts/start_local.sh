#!/bin/sh

python3 -m pip install --user virtualenv
cd ./vault_sdk
rm -rf venv
python3 -m venv env
source env/bin/activate
python3 -m pip install -I Flask==2.3.2 gunicorn==21.2.0 requests==2.31.0

# export DEBUG='true'
# export SKIP_TLS_VERIFY='false'
# export VAULT_REQUEST_TIMEOUT=20
# VAULT_REQUEST_RETRY_COUNT=5

gunicorn --keyfile ../certs/key.pem --certfile ../certs/cert.pem  --bind 0.0.0.0:8080 wsgi:app
deactivate