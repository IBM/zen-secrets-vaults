
import requests
from datetime import datetime, timedelta
import os
import time
import json
import sys
import logging

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
parent = os.path.dirname(parent)
sys.path.append(parent)

from vault_sdk.bridges_common.constants import *

SKIP_TLS_VERIFY = os.environ.get('SKIP_TLS_VERIFY', 'false')
VAULT_REQUEST_TIMEOUT = int(os.environ.get('VAULT_REQUEST_TIMEOUT', 20))

VAULT_REQUEST_RETRY_COUNT = int(os.environ.get('VAULT_REQUEST_RETRY_COUNT', 5))
VAULT_REQUEST_RETRY_BACKOFF_FACTOR = 0.5

def getCurrentFilename(file):
    return os.path.basename(file)
FILE_NAME = getCurrentFilename(__file__)

LOGGER = logging.getLogger("vaults")

# @param {flask.request} request — incoming request
#
# @returns {string} vault type
# @returns {array of string} vault auth content
# @returns {string} error message if any
# @returns {number} status code
def validateParams(request):
    try:
        secret_reference_metadata = request.args.get(SECRET_REFERENCE_METADATA, "")
        secret_type = request.args.get(SECRET_TYPE, "")
        vault_auth = request.headers.get(VAULT_AUTH_HEADER, "")
        transaction_id = request.headers.get(TRANSACTION_ID_HEADER, "No transaction ID")

        if secret_reference_metadata == "":
            target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
            return None, None, None, None, buildFrameworkExceptionPayload(f"{transaction_id}: Secret metadata is not found", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
        
        if secret_type == "":
            target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
            return None, None, None, None, buildFrameworkExceptionPayload(f"{transaction_id}: Secret type is not found", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
        
        if vault_auth == "":
            target = {"name": VAULT_AUTH_HEADER, "type": "header"}
            return None, None, None, None, buildFrameworkExceptionPayload(f"{transaction_id}: Vault auth header is not found", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
        
        return secret_reference_metadata, secret_type, vault_auth, transaction_id, None, None
    except Exception as err: 
        logFrameworkException(transaction_id, "validateParams()", FILE_NAME, str(err))
        return None, None, None, None, buildFrameworkExceptionPayload(str(err), E_9000, transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE
    

# @param {flask.request} request — incoming request
#
# @returns {string} vault type
# @returns {array of string} vault auth content
# @returns {string} error message if any
# @returns {number} status code
def validateParamsForBulkRequest(request):
    try:
        secret_reference_metadata = request.args.get(SECRET_REFERENCE_METADATA, "")
        vault_auth = request.headers.get(VAULT_AUTH_HEADER, "")
        transaction_id = request.headers.get(TRANSACTION_ID_HEADER, "No transaction ID")

        if secret_reference_metadata == "":
            target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
            return None, None, None, buildFrameworkExceptionPayload(f"{transaction_id}: Secret metadata is not found", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
        
        if vault_auth == "":
            target = {"name": VAULT_AUTH_HEADER, "type": "header"}
            return None, None, None, buildFrameworkExceptionPayload(f"{transaction_id}: Vault auth header is not found", E_1000, transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
        
        return secret_reference_metadata, vault_auth, transaction_id, None, None
    except Exception as err: 
        logFrameworkException(transaction_id, "validateParamsForBulkRequest()", FILE_NAME, str(err))
        return None, None, None, buildFrameworkExceptionPayload(str(err), E_9000, transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


# @param {vault} vault — vault object
# @param {dict} cached_token — dict of token {"token": "", "expiration": ""}
#
# @returns {string} access token
def getCachedToken(vault, cached_token):
    try:

        if cached_token is None:
            logDebug(vault, "getCachedToken()", FILE_NAME, "Cached token not found")
            return ""

        if datetime.fromtimestamp(cached_token["expiration"]) - timedelta(0,60) > datetime.now():
            logDebug(vault, "getCachedToken()", FILE_NAME, "Cached token found and not expired")
            return cached_token["token"]
        
        logDebug(vault, "getCachedToken()", FILE_NAME, "Cached token has expired")
        return ""
    except Exception as err: 
        logException(vault, "getCachedToken()", FILE_NAME, str(err))
        return ""


# @param {Flask.app} app 
# @param {string} message — error message
# @param {int} code — error code
#
# @returns {Flask.app.response_class} flask response
def buildExceptionResponse(app, message, code):
    dumped_message = json.dumps(message)
    logFrameworkException(None, "buildExceptionResponse()", FILE_NAME, dumped_message)
    return app.response_class(
            response=dumped_message,
            status=code,
            mimetype='application/json'
        )


# @param {string} message - error message 
# @param {string} code — error code
# @param {object} reqObj — reqObj
# @param {int} status_code — status_code
#
# @returns {dict} - error dict
def buildExceptionPayload(message, code, reqObj, status_code, target=None):
    trace = ""
    if reqObj != None:
        trace = reqObj.transaction_id
    return {
        "errors": [
            {
                "code": code,
                "message":message,
                "more_info": "https://github.com/IBM/zen-vault-bridge-sdk/apidoc",
                "target": target,
            }
        ],
        "status_code": status_code,
        "trace": trace
    }


# @param {string} message - error message 
# @param {string} code — error code
# @param {string} trace — transaction id
# @param {int} status_code — status_code
#
# @returns {dict} - error dict
def buildFrameworkExceptionPayload(message, code, trace, status_code, target=None):
    return {
        "errors": [
            {
                "code": code,
                "message":message,
                "more_info": "https://github.com/IBM/zen-vault-bridge-sdk/apidoc",
                "target": target,
            }
        ],
        "status_code": status_code,
        "trace": trace
    }


# @param {int} index - thread index
# @param {vault object} vault — the vault object
# @param {array} response_data — response_data data array
#
# @returns None
def bulkThreadFunction(index, vault, response_data):
    logDebug(vault, "bulkThreadFunction()", FILE_NAME, f"Thread - {index} of vault {vault.secret_urn} is running")

    error, _ = vault.extractFromVaultAuthHeader()
    if error is not None:
        error[SECRET_URN] = vault.secret_urn
        response_data.append(error)
        return

    extracted_secret, error, _ = vault.processRequestGetSecret(True)
    if error is not None:
        error[SECRET_URN] = vault.secret_urn
        response_data.append(error)
        return
    
    response_data.append(extracted_secret)
    logDebug(vault, "bulkThreadFunction()", FILE_NAME, f"Thread - {index} of vault {vault.secret_urn} is finished")



# @param {string} url - request url
# @param {dict} headers — request header
# @param {dict} data — request data
#
# @returns {python response object} response
def sendGetRequest(url, headers, data):
    retry = 1

    while retry <= VAULT_REQUEST_RETRY_COUNT:
        response = requests.get(url, headers=headers, data=data, verify=SKIP_TLS_VERIFY=='false', timeout=VAULT_REQUEST_TIMEOUT)
        logFrameworkDebug(None, "sendGetRequest()", FILE_NAME, f"send_get_request to {url}, and get response: {response}")

        # retry the request if response status code in RETRY_ERROR_CODE_LIST
        if response.status_code in RETRY_ERROR_CODE_LIST:
            retry_delay = VAULT_REQUEST_RETRY_BACKOFF_FACTOR * (2 ** (retry))
            if retry >= VAULT_REQUEST_RETRY_COUNT:
                break
            logFrameworkDebug(None, "sendGetRequest()", FILE_NAME, f"receive {response.status_code}, and tried {retry} times, and retry delay is {retry_delay}")
            retry = retry + 1
            time.sleep(retry_delay)
        else:
            break
    return response


def sendPostRequest(url, headers, data):
    retry = 1

    while retry <= VAULT_REQUEST_RETRY_COUNT:
        response = requests.post(url, headers=headers, data=data, verify=SKIP_TLS_VERIFY=='false', timeout=VAULT_REQUEST_TIMEOUT)
        logFrameworkDebug(None, "sendPostRequest()", FILE_NAME, f"send_get_request to {url}, and get response: {response}")
        
        # retry the request if response status code in RETRY_ERROR_CODE_LIST
        if response.status_code in RETRY_ERROR_CODE_LIST:
            if retry >= VAULT_REQUEST_RETRY_COUNT:
                break
            retry_delay = VAULT_REQUEST_RETRY_BACKOFF_FACTOR * (2 ** (retry))
            logFrameworkDebug(None, "sendPostRequest()", FILE_NAME, f"receive {response.status_code}, and tried {retry} times, and retry delay is {retry_delay}")
            retry = retry + 1
            time.sleep(retry_delay)
        else:
            break
    return response


def extractReqObj(reqObj):
    if reqObj == None:
        return ""
    return f"[TransactionID={reqObj.transaction_id}]  [SecretUrn={reqObj.secret_urn}]"

def logException(reqObj, func_name, file_name, message):
    LOGGER.error(f"{extractReqObj(reqObj)} {file_name}:{func_name} - {message}")


def logInfo(reqObj, func_name, file_name, message):
    LOGGER.info(f"{extractReqObj(reqObj)} {file_name}:{func_name} - {message}")


def logDebug(reqObj, func_name, file_name, message):
    LOGGER.debug(f"{extractReqObj(reqObj)} {file_name}:{func_name} - {message}")


def logFrameworkException(transaction_id, func_name, file_name, message):
    trans_section = ""
    if transaction_id != None:
        trans_section = f"[TransactionID={transaction_id}]"
    LOGGER.error(f"{trans_section} {file_name}:{func_name} - {message}")


def logFrameworkDebug(transaction_id, func_name, file_name, message):
    trans_section = ""
    if transaction_id != None:
        trans_section = f"[TransactionID={transaction_id}]"
    LOGGER.debug(f"{trans_section} {file_name}:{func_name} - {message}")