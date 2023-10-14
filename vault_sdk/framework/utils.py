
import requests
from datetime import datetime, timedelta
import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization
import os
import time
import json
import sys
import jwt
import logging
from jwt import InvalidTokenError
from pathlib import Path

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
parent = os.path.dirname(parent)
sys.path.append(parent)

from vault_sdk.framework.error_codes import COMPONENT_EXCEPTIONS
from vault_sdk.bridges_common.constants import *
from vault_sdk.framework import caches

SKIP_TLS_VERIFY = os.environ.get('SKIP_TLS_VERIFY', 'false')
VAULT_REQUEST_TIMEOUT = int(os.environ.get('VAULT_REQUEST_TIMEOUT', 20))

VAULT_REQUEST_RETRY_COUNT = int(os.environ.get('VAULT_REQUEST_RETRY_COUNT', 5))
VAULT_REQUEST_RETRY_BACKOFF_FACTOR = 0.5

GIT_REPO_URL = os.environ.get('MOR_INFO_PREFIX', "https://github.com/IBM/zen-vault-bridge-sdk")
ERROR_DOC_PATH = os.environ.get('ERROR_DOC_PATH', "/blob/main/docs/apidoc/error_codes.md")

def getCurrentFilename(file):
    return os.path.basename(file)
FILE_NAME = getCurrentFilename(__file__)

LOGGER = logging.getLogger("vaults")

# @sets env variable PUBLIC_KEY_ERROR_MESSAGE
# @sets env variable PUBLIC_KEY
def load_jwt_public_keys():
    public_key_path = os.getenv(JWT_PUBLIC_KEY_PATH)
    if not public_key_path:
        raise RuntimeError("JWT_PUBLIC_KEY_PATH environment variable is not set")

    pem_file = Path(public_key_path)

    if not pem_file.is_file():
        raise RuntimeError(f"No such file: {public_key_path}")

    try:
        with pem_file.open('r') as f:
            public_key_str = f.read()
        global JWT_PUBLIC_KEY_VALUE 
        JWT_PUBLIC_KEY_VALUE = serialization.load_pem_public_key(public_key_str.encode(), backend=cryptography.hazmat.backends.default_backend())
    except Exception as e: 
        raise RuntimeError(f"Got error in function load_jwt_public_keys(): {str(e)}")


# @param auth_header
#
# @returns {string} extracted token
# @returns {string} error message if any
def extractBearerToken(auth_header):

    parts = auth_header.split()

    if len(parts) == 2 and parts[0] == "Bearer":
        token = parts[1]
        return token, None, None
    else:
        target = {"name": AUTHORIZATION_HEADER, "type": "header"}
        return "", buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["code"], "", COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["http_status_code"]

# @param {flask.request} request — incoming request
# @param {logging} logging — python logging handler
#
# @returns {string} Payload
# @returns {string} error message if any
# @returns {number} status code
def validateJWT(token, public_key, transaction_id):

    exceptionTarget = {"name": AUTHORIZATION_HEADER, "type": "header"}

    try:
        payload = jwt.decode(token, public_key, algorithms=["RS256"], audience=ZEN_VAULT_BRIDGE)

        return payload, None, None

    except InvalidTokenError as e:
        return None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["code"], "", COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["http_status_code"], exceptionTarget), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10001"]["http_status_code"]
    except Exception as e:   
        logFrameworkException(transaction_id, "validateJWT()", FILE_NAME, f"Got error in function validateJWT(): {str(e)}")
        return None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["code"], "", COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["http_status_code"], exceptionTarget), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["http_status_code"]



# @param {any} HttpHeader
#
# @returns {string} token
# @returns {string} error message if any
# @returns {number} status code
def authenticate(HttpHeader):
    auth_header = HttpHeader.get(AUTHORIZATION_HEADER)
    transaction_id = HttpHeader.get(TRANSACTION_ID_HEADER)
    token, error, code = extractBearerToken(auth_header)
    if error is not None:
        return None, error, code
    
    public_key = JWT_PUBLIC_KEY_VALUE
     
    token, error, code = validateJWT(token, public_key, transaction_id)
    if error is not None:
        return None, error, code
    return  token, None, None 

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
        authorization_header = request.headers.get(AUTHORIZATION_HEADER, "")


        if secret_reference_metadata == "":
            target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
            return None, None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["http_status_code"]
        
        if secret_type == "":
            target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
            return None, None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10502"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10502"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10502"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10502"]["http_status_code"]
        
        if vault_auth == "":
            target = {"name": VAULT_AUTH_HEADER, "type": "header"}
            return None, None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"]
        
        if authorization_header == "":
            target = {"name": AUTHORIZATION_HEADER, "type": "header"}
            return None, None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"]
        
        return secret_reference_metadata, secret_type, vault_auth, transaction_id, None, None
    except Exception as err: 
        logFrameworkException(transaction_id, "validateParams()", FILE_NAME, str(err))
        return None, None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["http_status_code"]), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["http_status_code"]
    

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
        authorization_header = request.headers.get(AUTHORIZATION_HEADER, "")

        if secret_reference_metadata == "":
            target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
            return None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10503"]["http_status_code"]
        
        if vault_auth == "":
            target = {"name": VAULT_AUTH_HEADER, "type": "header"}
            return None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"]
        
        if authorization_header == "":
            target = {"name": AUTHORIZATION_HEADER, "type": "header"}
            return None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"], target), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10501"]["http_status_code"]
        
        return secret_reference_metadata, vault_auth, transaction_id, None, None
    except Exception as err: 
        logFrameworkException(transaction_id, "validateParamsForBulkRequest()", FILE_NAME, str(err))
        return None, None, None, buildFrameworkExceptionPayload(COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["message"], COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["code"], transaction_id, COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["http_status_code"]), COMPONENT_EXCEPTIONS["vaultbridgesdk_e_10900"]["http_status_code"]


# @param {string} vault_type — vault type
# @param {string} key — key of vault token
# @param {string} transaction_id — transaction id of current request
#
# @returns {string} access token
def getCachedToken(vault_type, key, transaction_id):
    try:
        if vault_type not in caches.CACHED_TOKEN:
            return ""

        if key not in caches.CACHED_TOKEN[vault_type]:
            return ""

        cached_token = caches.CACHED_TOKEN[vault_type][key]

        if datetime.fromtimestamp(cached_token["expiration"]) - timedelta(0,60) > datetime.now():
            logFrameworkDebug(transaction_id, "getCachedToken()", FILE_NAME, "Cached token found and not expired")
            return cached_token["token"]

        logFrameworkDebug(transaction_id, "getCachedToken()", FILE_NAME, "Cached token has expired")
        return ""
    except Exception as err: 
        logFrameworkException(transaction_id, "getCachedToken()", FILE_NAME, str(err))
        return ""


# @param {string} vault_type — vault type
# @param {string} key — key of vault token
# @param {string} transaction_id — transaction id of current request
# 
# store the token to caches
def saveTokenInCache(vault_type, key, token, transaction_id):
    try:
        if vault_type not in caches.CACHED_TOKEN:
            caches.CACHED_TOKEN[vault_type] = {}
        caches.CACHED_TOKEN[vault_type][key] = token

        return
    except Exception as err: 
        logFrameworkException(transaction_id, "saveTokenInCache()", FILE_NAME, str(err))
        return


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
                "more_info": GIT_REPO_URL+ERROR_DOC_PATH+"#"+code,
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
                "more_info": GIT_REPO_URL+ERROR_DOC_PATH+"#"+code,
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