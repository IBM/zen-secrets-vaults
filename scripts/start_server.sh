#!/bin/sh

cert_path="--certfile /certs/key.pem"
key_path="--keyfile /certs/cert.pem"

if [ ! -z "$TLS_CERTITICATE_FILE_PATH" ] && [ ! -z "$TLS_KEY_FILE_PATH" ]; then
    cert_path="--certfile $TLS_CERTITICATE_FILE_PATH"
    key_path="--keyfile $TLS_KEY_FILE_PATH"
fi

cd ./vault_sdk 
gunicorn $key_path $cert_path --bind 0.0.0.0:8080 wsgi:app