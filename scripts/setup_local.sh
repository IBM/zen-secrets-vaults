#!/bin/sh

cd ./vault_sdk

rm -rf "../certs"
mkdir -p "../certs/jwt"

export TLS_KEY_FILE_PATH="../certs/key.pem"
export TLS_CERTIFICATE_FILE_PATH="../certs/cert.pem"
export JWT_PUBLIC_KEY_PATH="../certs/jwt/public.pem"

openssl req -x509 -newkey rsa:4096 -keyout ${TLS_KEY_FILE_PATH} -out ${TLS_CERTIFICATE_FILE_PATH} -sha256 -days 3650 -nodes -subj "/C=US/ST=CA/L=SANJOSE/O=IBM/OU=IBM/CN=vault-bridge-server"

python3 -m pip install --user virtualenv
rm -rf venv
python3 -m venv env
source env/bin/activate
python3 -m pip install -I Flask==2.3.2 gunicorn==21.2.0 requests==2.31.0 pyjwt[crypto]