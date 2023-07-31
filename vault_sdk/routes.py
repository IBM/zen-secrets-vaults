from flask import Flask, request, json
from utils import validateParams, buildErrorResponse, buildErrorDict
from logging.config import dictConfig
import os
from constants import *
from bridge_lookup import CLASS_LOOKUP

LOGGING_LEVEL = os.environ.get('LOGGING_LEVEL', 'INFO')
if LOGGING_LEVEL not in LOGGING_LEVEL_LIST:
    LOGGING_LEVEL = 'INFO'

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': LOGGING_LEVEL,
        'handlers': ['wsgi']
    }
})
app = Flask(__name__)
logging = app.logger



# GET /health
# RESPONSE "OK" HTTP_SUCCESS_CODE
@app.route("/health", methods=["GET"])
def health():
    return json.dumps({"status": "OK"})


# GET /v2/vaults/<vault_type>/secrets/<secret_urn>
# @url_param {string} vault_type - value from {ibm-secret-manager|aws-secrets-manager|azure-kv-vault}
# @url_param {string} secret_urn 
#
# @query_param {string} secret_metadata - b64 encoded secret reference
# @query_param {string} secret_type - value from {credentials|certificate|generic|key}
#
# @header {string} VAULT-AUTH - <IAM_URL=;VAULT_URL=;API_KEY=;> Note: value need to be separated by semicolon
# 
# SUCCESS RESPONSE {SECRET_JSON_STRING} HTTP_SUCCESS_CODE
@app.route("/v2/vaults/<vault_type>/secrets/<secret_urn>", methods=["GET"])
def get_secret(vault_type, secret_urn):

    logging.debug(f"Receiving request for secret {secret_urn} with vault type {vault_type}")

    secret_metadata, secret_type, auth_string, error, code = validateParams(request, logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)
    
    if vault_type not in VAULT_TYPES:
        return buildErrorResponse(app, buildErrorDict(f"vault type {vault_type} is not supported"), HTTP_BAD_REQUEST_CODE, logging)
    
    if secret_type not in SECRET_TYPES[IBM_SECRETS_MANAGER]:
        return buildErrorResponse(app, buildErrorDict(f"secret type {secret_type} is not supported"), HTTP_BAD_REQUEST_CODE, logging)

    vault = CLASS_LOOKUP[vault_type](secret_metadata, secret_type, secret_urn, auth_string)
    
    error, code = vault.extractFromVaultAuthHeader(logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)

    extracted_secret, error, code = vault.processRequestGetSecret(logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)

    logging.debug(f"Sending response for secret {secret_urn} with vault type {vault_type}")
    return json.dumps(extracted_secret)