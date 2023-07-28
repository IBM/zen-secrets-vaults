import requests
from datetime import datetime, timedelta
import os
import time
import json
import sys

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from vault_sdk.constants import *
from vault_sdk import caches

SKIP_TLS_VERIFY = os.environ.get('SKIP_TLS_VERIFY', 'false')
VAULT_REQUEST_TIMEOUT = int(os.environ.get('VAULT_REQUEST_TIMEOUT', 20))

VAULT_REQUEST_RETRY_COUNT = int(os.environ.get('VAULT_REQUEST_RETRY_COUNT', 20))
VAULT_REQUEST_RETRY_BACKOFF_FACTOR = 0.5


# @param {flask.request} request — incoming request
# @param {logging} logging — python logging handler
# @param {bool} is_bulk — is bulk operation
#
# @returns {string} vault type
# @returns {array of string} vault auth content
# @returns {string} error message if any
# @returns {number} status code
def validateParams(request, logging):
    try:
        secret_metadata = request.args.get('secret_metadata', "")
        secret_type = request.args.get('secret_type', "")
        vault_auth = request.headers.get('VAULT-AUTH', "")

        if secret_metadata == "":
            return None, None, None, buildErrorDict(f"Secret metadata is not found"), HTTP_BAD_REQUEST_CODE
        
        if secret_type == "":
            return None, None, None, buildErrorDict(f"Secret type is not found"), HTTP_BAD_REQUEST_CODE
        
        if vault_auth == "":
            return None, None, None, buildErrorDict(f"Vault auth header is not found"), HTTP_BAD_REQUEST_CODE
        
        return secret_metadata, secret_type, vault_auth, None, None
    except Exception as err: 
        logging.error(f"Got error in function validateParams(): {str(err)}")
        return None, None, None, buildErrorDict(str(err)), HTTP_INTERNAL_SERVER_ERROR_CODE


# @param {logging} logging — python logging handler
#
# @returns {string} access token
def getCachedToken(vault, logging):
    try:
        token_dict = caches.TOKEN[vault.vault_type]
        apikey_entry = token_dict.get(vault.auth[API_KEY], None)
        if apikey_entry is None:
            logging.debug(f"{vault.secret_urn}: Cached token not found")
            return ""

        if datetime.fromtimestamp(apikey_entry["expiration"]) + timedelta(0,60) > datetime.now():
            logging.debug(f"Cached token found and not expired")
            return apikey_entry["token"]
        
        logging.debug(f"{vault.secret_urn}: Cached token has expired")
        return ""
    except Exception as err: 
        logging.error(f"Got error in function getCachedToken(): {str(err)}")
        return ""


# @param {Flask.app} app 
# @param {string} message — error message
# @param {int} code — error code
#
# @returns {Flask.app.response_class} flask response
def buildErrorResponse(app, message, code, logging):
    dumped_message = json.dumps(message)
    logging.error(dumped_message)
    return app.response_class(
            response=json.dumps(dumped_message),
            status=code,
            mimetype='application/json'
        )


def buildErrorDict(message):
    return {"errors": message}


# @param {string} url - request url
# @param {dict} headers — request header
# @param {dict} data — request data
# @param {logging} logging — python logging handler
#
# @returns {python response object} response
def sendGetRequest(url, headers, data, logging):
    retry = 1

    while retry <= VAULT_REQUEST_RETRY_COUNT:
        response = requests.get(url, headers=headers, data=data, verify=SKIP_TLS_VERIFY=='false', timeout=VAULT_REQUEST_TIMEOUT)
        logging.debug(f"send_get_request to {url}, and get response: {response}")

        # retry the request if response status code in RETRY_ERROR_CODE_LIST
        if response.status_code in RETRY_ERROR_CODE_LIST:
            retry_delay = VAULT_REQUEST_RETRY_BACKOFF_FACTOR * (2 ** (retry))
            if retry >= VAULT_REQUEST_RETRY_COUNT:
                break
            logging.debug(f"receive {response.status_code}, and tried {retry} times, and retry delay is {retry_delay}")
            retry = retry + 1
            time.sleep(retry_delay)
        else:
            break
    return response


def sendPostRequest(url, headers, data, logging):
    retry = 1

    while retry <= VAULT_REQUEST_RETRY_COUNT:
        response = requests.post(url, headers=headers, data=data, verify=SKIP_TLS_VERIFY=='false', timeout=VAULT_REQUEST_TIMEOUT)
        logging.debug(f"send_get_request to {url}, and get response: {response}")
        
        # retry the request if response status code in RETRY_ERROR_CODE_LIST
        if response.status_code in RETRY_ERROR_CODE_LIST:
            if retry >= VAULT_REQUEST_RETRY_COUNT:
                break
            retry_delay = VAULT_REQUEST_RETRY_BACKOFF_FACTOR * (2 ** (retry))
            logging.debug(f"receive {response.status_code}, and tried {retry} times, and retry delay is {retry_delay}")
            retry = retry + 1
            time.sleep(retry_delay)
        else:
            break
    return response