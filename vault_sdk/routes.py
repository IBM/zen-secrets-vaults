from flask import Flask, request, json
from utils import validateParams, validateParamsForBulkRequest, buildErrorResponse, buildErrorPayload, bulkThreadFunction
from logging.config import dictConfig
import os
from constants import *
from bridge_lookup import CLASS_LOOKUP
import base64
import threading

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
@app.route("/v2/health", methods=["GET"])
def health():
    return json.dumps({"status": "OK"})


# GET /v2/vault-bridges/<vault_type>/secrets/<secret_urn>
# @url_param {string} vault_type - value from {ibm-secret-manager|aws-secrets-manager|azure-kv-vault}
# @url_param {string} secret_urn 
#
# @query_param {string} secret_reference_metadata - b64 encoded json string of secret reference metadata
# @query_param {string} secret_type - value from {credentials|certificate|generic|key}
# @query_param {bool} validate - if this is set to true then bridge returns generic format response without matching CPD secret type with vault secret type
#
# @header {string} Vault-Auth - <IAM_URL=;VAULT_URL=;API_KEY=;> Note: value need to be separated by semicolon
# @header {string} IBM-CPD-Transaction-ID - transaction id
# 
# SUCCESS RESPONSE {SECRET_JSON_STRING} HTTP_SUCCESS_CODE
@app.route("/v2/vault-bridges/<vault_type>/secrets/<secret_urn>", methods=["GET"])
def get_secret(vault_type, secret_urn):

    logging.debug(f"Receiving request for secret {secret_urn} with vault type {vault_type}")

    secret_reference_metadata, secret_type, is_validate, auth_string, transaction_id, error, code = validateParams(request, logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)
    
    if vault_type not in VAULT_TYPES:
        target = {"name": VAULT_TYPE, "type": "parameter"}
        return buildErrorResponse(app, buildErrorPayload(f"{transaction_id}: vault type {vault_type} is not supported", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE, logging)
    
    if secret_type not in SECRET_TYPES[IBM_SECRETS_MANAGER]:
        target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
        return buildErrorResponse(app, buildErrorPayload(f"{transaction_id}: secret type {secret_type} is not supported", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE, logging)

    vault = CLASS_LOOKUP[vault_type](secret_reference_metadata, secret_type, secret_urn, auth_string, transaction_id, is_validate)
    error, code = vault.extractFromVaultAuthHeader(logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)
    
    error, code = vault.extractSecretReferenceMetadata(logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)

    extracted_secret, error, code = vault.processRequestGetSecret(logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)

    logging.debug(f"Sending response for transaction {transaction_id} and secret {secret_urn} with vault type {vault_type}")
    return json.dumps(extracted_secret)


# GET /v2/vault-bridges/<vault_type>/secrets/bulk
# @url_param {string} vault_type - value from {ibm-secret-manager|aws-secrets-manager|azure-kv-vault}
#
# @query_param {string} secret_reference_metadata - b64 encoded secret references <secret_reference_metadata...> Note: value need to be separated by semicolon
#
# @header {string} Vault-Auth - <IAM_URL=;VAULT_URL=;API_KEY=;> Note: value need to be separated by semicolon
# @header {string} IBM-CPD-Transaction-ID - transaction id
# 
# SUCCESS RESPONSE {SECRET_JSON_STRING} 200
@app.route("/v2/vault-bridges/<vault_type>/secrets/bulk", methods=["GET"])
def get_bulk_secret(vault_type):

    secret_reference_metadata, auth_string, transaction_id, error, code = validateParamsForBulkRequest(request, logging)
    if error is not None:
        return buildErrorResponse(app, error, code, logging)
    
    if vault_type not in VAULT_TYPES:
        target = {"name": VAULT_TYPE, "type": "parameter"}
        return buildErrorResponse(app, buildErrorPayload(f"{transaction_id}: vault type {vault_type} is not supported", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE, logging)
    
    try:
        secret_reference_metadata_list = json.loads(base64.b64decode(secret_reference_metadata).decode('utf-8'))
    except Exception as err: 
        logging.error(f"{transaction_id}: Got error: {str(err)}")
        return buildErrorResponse(app, buildErrorPayload(str(err), E_9000, transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE, logging)
    
    response_data = []
    index = 0
    threads = list()
    while index < len(secret_reference_metadata_list):
        vault = CLASS_LOOKUP[vault_type](secret_reference_metadata_list[index], "", "", auth_string, transaction_id)
        error, code = vault.extractSecretReferenceMetadataBulk(logging)
        if error is not None:
            return buildErrorResponse(app, error, code, logging)

        # have separate thread to handle the request
        t = threading.Thread(target=bulkThreadFunction, args=(index, vault, response_data, logging))
        threads.append(t)
        t.start()
        index=index+1
    
    # waiting for thread to be finished
    for index, thread in enumerate(threads):
        logging.debug(f"Main: before joining thread {index}")
        thread.join()
        logging.debug(f"Main: thread {index} done")

    logging.debug(f"Sending response for the bulk request with secret {transaction_id} with vault type {vault_type}")
    return json.dumps(response_data)
