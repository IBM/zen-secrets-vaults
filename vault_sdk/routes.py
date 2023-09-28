from flask import Flask, request, json
import logging
from framework.utils import validateParams, validateParamsForBulkRequest, buildExceptionResponse, buildFrameworkExceptionPayload, \
                            bulkThreadFunction, logFrameworkDebug, logFrameworkException, getCurrentFilename
from bridges_common.constants import *
from bridges_common.bridge_lookup import CLASS_LOOKUP
import os
import base64
import threading
import sys

LOGGING_LEVEL = os.environ.get('LOGGING_LEVEL', 'INFO')
if LOGGING_LEVEL not in LOGGING_LEVEL_LIST:
    LOGGING_LEVEL = 'INFO'

app = Flask('vaults')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s'))
app.logger.handlers.clear()
app.logger.addHandler(handler)
app.logger.setLevel(LOGGING_LEVEL)

FILE_NAME = getCurrentFilename(__file__)

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
# @header {string} Vault-Auth - <VAULT_URL=;API_KEY=;> Note: value need to be separated by semicolon
# @header {string} IBM-CPD-Transaction-ID - transaction id
# 
# SUCCESS RESPONSE {SECRET_JSON_STRING} HTTP_SUCCESS_CODE
@app.route("/v2/vault-bridges/<vault_type>/secrets/<secret_urn>", methods=["GET"])
def get_secret(vault_type, secret_urn):

    secret_reference_metadata, secret_type, auth_string, transaction_id, error, code = validateParams(request)
    if error is not None:
        return buildExceptionResponse(app, error, code)
    
    logFrameworkDebug(transaction_id, "get_secret()", FILE_NAME, f"Receiving request for secret {secret_urn} with vault type {vault_type}")
    
    if vault_type not in VAULT_TYPES:
        target = {"name": VAULT_TYPE, "type": "parameter"}
        return buildExceptionResponse(app, buildFrameworkExceptionPayload(f"{transaction_id}: vault type {vault_type} is not supported", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE)
    
    if secret_type not in SECRET_TYPES[vault_type]:
        target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
        return buildExceptionResponse(app, buildFrameworkExceptionPayload(f"{transaction_id}: secret type {secret_type} is not supported", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE)

    vault = CLASS_LOOKUP[vault_type](secret_reference_metadata, secret_type, secret_urn, auth_string, transaction_id)
    error, code = vault.extractFromVaultAuthHeader()
    if error is not None:
        return buildExceptionResponse(app, error, code)
    
    error, code = vault.extractSecretReferenceMetadata()
    if error is not None:
        return buildExceptionResponse(app, error, code)

    extracted_secret, error, code = vault.processRequestGetSecret()
    if error is not None:
        return buildExceptionResponse(app, error, code)

    logFrameworkDebug(transaction_id, "get_secret()", FILE_NAME, f"Sending response for transaction {transaction_id} and secret {secret_urn} with vault type {vault_type}")
    return json.dumps(extracted_secret)


# GET /v2/vault-bridges/<vault_type>/secrets/bulk
# @url_param {string} vault_type - value from {ibm-secret-manager|aws-secrets-manager|azure-kv-vault}
#
# @query_param {string} secret_reference_metadata - b64 encoded secret references <secret_reference_metadata...> Note: value need to be separated by semicolon
#
# @header {string} Vault-Auth - <VAULT_URL=;API_KEY=;> Note: value need to be separated by semicolon
# @header {string} IBM-CPD-Transaction-ID - transaction id
# 
# SUCCESS RESPONSE {SECRET_JSON_STRING} 200
@app.route("/v2/vault-bridges/<vault_type>/secrets/bulk", methods=["GET"])
def get_bulk_secret(vault_type):

    secret_reference_metadata, auth_string, transaction_id, error, code = validateParamsForBulkRequest(request)
    if error is not None:
        return buildExceptionResponse(app, error, code)
    
    if vault_type not in VAULT_TYPES:
        target = {"name": VAULT_TYPE, "type": "parameter"}
        return buildExceptionResponse(app, buildFrameworkExceptionPayload(f"{transaction_id}: vault type {vault_type} is not supported", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE)
    
    try:
        secret_reference_metadata_list = json.loads(base64.b64decode(secret_reference_metadata).decode('utf-8'))
    except Exception as err: 
        logFrameworkException(transaction_id, "get_bulk_secret()", FILE_NAME, f"{transaction_id}: get_bulk_secret() Got error: {str(err)}")
        return buildExceptionResponse(app, buildFrameworkExceptionPayload(str(err), E_9000, transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE)
    
    response_data = []
    index = 0
    threads = list()
    while index < len(secret_reference_metadata_list):
        vault = CLASS_LOOKUP[vault_type](secret_reference_metadata_list[index], "", "", auth_string, transaction_id)
        error, code = vault.extractSecretReferenceMetadataBulk()
        if error is not None:
            return buildExceptionResponse(app, error, code)

        # have separate thread to handle the request
        t = threading.Thread(target=bulkThreadFunction, args=(index, vault, response_data))
        threads.append(t)
        t.start()
        index=index+1
    
    # waiting for thread to be finished
    for index, thread in enumerate(threads):
        logFrameworkDebug(transaction_id, "get_bulk_secret()", FILE_NAME, f"Main: before joining thread {index}")
        thread.join()
        logFrameworkDebug(transaction_id, "get_bulk_secret()", FILE_NAME, f"Main: thread {index} done")

    logFrameworkDebug(transaction_id, "get_bulk_secret()", FILE_NAME, f"Sending response for the bulk request with secret {transaction_id} with vault type {vault_type}")
    return json.dumps(response_data)
