import json
import base64
import os
import sys

# include parent paths, so the module can be imported
current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
parent = os.path.dirname(parent)
parent = os.path.dirname(parent)
sys.path.append(parent)

from vault_sdk.bridges.ibm_secrets_manager.constants import *
from vault_sdk.bridges_common.constants import *
from vault_sdk.bridges.ibm_secrets_manager.error_codes import COMPONENT_EXCEPTIONS
from vault_sdk.framework.utils import getCachedToken, saveTokenInCache, sendGetRequest, sendPostRequest, buildExceptionPayload, logException, logDebug, getCurrentFilename

FILE_NAME = getCurrentFilename(__file__)

class IBMSecretManager(object):
    def __init__(self, secret_reference_metadata, secret_type, secret_urn, auth_string, transaction_id):
        self.vault_type = IBM_SECRETS_MANAGER
        self.secret_reference_metadata = secret_reference_metadata
        self.secret_type = secret_type
        self.secret_urn = secret_urn
        self.auth_string = auth_string
        self.transaction_id = transaction_id
        self.secret_id = ""
        self.error_codes = COMPONENT_EXCEPTIONS


    # @returns {string} error message if any
    #
    # this function extract secret_id from request query param secret_reference_metadata
    def extractSecretReferenceMetadata(self):
        try:
            decoded_secret_metadata = json.loads(base64.b64decode(self.secret_reference_metadata).decode('utf-8'))
            secret_id = decoded_secret_metadata.get(SECRET_ID, "")

            if secret_id == "":
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildExceptionPayload("vaultbridgesdk_e_22102", self, target), HTTP_NOT_FOUND_CODE
            
            self.secret_id = secret_id
            return None, None
        except Exception as err: 
            logException(self, "extractSecretReferenceMetadata()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
        

    # @returns {string} error message if any
    #
    # this function extract secret_id, secret_urn, and secret_type from request query param secret_reference_metadata
    def extractSecretReferenceMetadataBulk(self):
        try:
            secret_urn = self.secret_reference_metadata.get(SECRET_URN, "")
            secret_id = self.secret_reference_metadata.get(SECRET_ID, "")
            secret_type = self.secret_reference_metadata.get(SECRET_TYPE, "")

            if secret_urn == "" or secret_id == "" or secret_type == "":
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildExceptionPayload("vaultbridgesdk_e_22200", self, target), HTTP_NOT_FOUND_CODE

            if secret_type not in SECRET_TYPES[IBM_SECRETS_MANAGER]:
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildExceptionPayload("vaultbridgesdk_e_22103", self, target), HTTP_NOT_FOUND_CODE

            self.secret_id = secret_id
            self.secret_urn = secret_urn
            self.secret_type = secret_type

            return None, None
        except Exception as err: 
            logException(self, "extractSecretReferenceMetadataBulk()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
    
    

    # @returns {string} error message if any
    def extractFromVaultAuthHeader(self):
        try:
            decoded_auth_header = base64.b64decode(self.auth_string).decode('utf-8')

            auth_list = decoded_auth_header.split(";")
            if len(auth_list) < 2:
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildExceptionPayload("vaultbridgesdk_e_22001", self, target), HTTP_NOT_FOUND_CODE
            
            self.auth = {}
            for item in auth_list:
                temp = item.split("=")
                if len(temp) < 2:
                    target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                    return buildExceptionPayload("vaultbridgesdk_e_22001", self, target), HTTP_NOT_FOUND_CODE
                self.auth[temp[0]] = temp[1]

            if self.auth.get(VAULT_URL, "") == "" or self.auth.get(API_KEY, "") == "":
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildExceptionPayload("vaultbridgesdk_e_22002", self, target), HTTP_NOT_FOUND_CODE

            self.auth[IBM_CLOUD_IAM_URL] = os.environ.get('IBM_CLOUD_IAM_URL', DEFAULT_IBM_CLOUD_IAM_URL)
            self.cache_key = self.auth[API_KEY]

            return None, None
        except Exception as err: 
            logException(self, "extractFromVaultAuthHeader()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {bool} is_bulk — true if this is a bulk request
    #
    # @returns {dict} extracted_secret - secret in python dict format
    # @returns {string} error message if any
    # @returns {number} status code
    def processRequestGetSecret(self, is_bulk=False):
        try:
            token, error, code = self.getAccessToken()
            if error is not None:
                return None, error, code
            
            secret, error, code = self.getSecret(token)
            if error is not None:
                return None, error, code
            
            extracted_secret, error, code = self.extractSecret(secret, is_bulk)
            if error is not None:
                return None, error, code
            
            return extracted_secret, None, None
        except Exception as err: 
            logException(self, "processRequestGetSecret()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @returns {string} token
    # @returns {string} error message if any
    # @returns {number} status code
    def getAccessToken(self):
        try:
            cached_token = getCachedToken(IBM_SECRETS_MANAGER, self.cache_key, self.transaction_id)
            if cached_token != "":
                return cached_token, None, None

            # if no cached token is found, then send request to get a new token
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
            data = {
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self.auth[API_KEY]
            }

            response = sendPostRequest(self.auth[IBM_CLOUD_IAM_URL], headers, data)
            # return error if the request failed
            if response.status_code != HTTP_SUCCESS_CODE:
                logException(self, "getAccessToken()", FILE_NAME, f"{response.text} and status code {response.status_code} returned from {self.auth[IBM_CLOUD_IAM_URL]}")
                return None, buildExceptionPayload("vaultbridgesdk_e_22501", self), HTTP_INTERNAL_SERVER_ERROR_CODE
            
            
            data = json.loads(response.text)

            if "access_token" not in data or "expiration" not in data:
                logException(ERROR_TOKEN_NOT_RETURNED)
                return None, buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE

            # store token to cache
            token = {"token": data["access_token"], "expiration": data["expiration"]}
            saveTokenInCache(IBM_SECRETS_MANAGER, self.cache_key, token, self.transaction_id)

            return token["token"], None, None
        except Exception as err: 
            logException(self, "getAccessToken()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @returns {string} response body
    # @returns {string} error message if any
    # @returns {number} status code    
    def getSecret(self, token):
        try:
            logDebug(self, "getSecret()", FILE_NAME, "Sending request to get the secret")
            headers = {
                "Authorization": "Bearer " + token,
                "Accept": "application/json"
            }

            response = sendGetRequest(self.auth[VAULT_URL]+"/api/v2/secrets/"+self.secret_id, headers, None)
            if response.status_code != HTTP_SUCCESS_CODE:
                logException(self, "getSecret()", FILE_NAME, f"{response.text} and status code {response.status_code} returned from {self.auth[VAULT_URL]}")
                return None, buildExceptionPayload("vaultbridgesdk_e_22501", self), HTTP_INTERNAL_SERVER_ERROR_CODE

            return response.text, None, None
        except Exception as err: 
            logException(self, "getSecret()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
        

    # @param {string} secret — secret content in string
    # @param {bool} is_bulk — true if this is a bulk request
    #
    # @returns {dict} response - content of response
    # @returns {string} error message if any
    # @returns {number} status code
    def extractSecret(self, secret, is_bulk=False):
        try:
            logDebug(self, "extractSecret()", FILE_NAME, "Extracting secret data")
            extracted_secret = json.loads(secret)
            ibm_secret_type = extracted_secret[SECRET_TYPE] 

            response_secret_data = {}
            get_secret = False

            if (self.secret_type == "credentials" or self.secret_type == "generic") and ibm_secret_type == "username_password":
                username = extracted_secret.get("username", "")
                password = extracted_secret.get("password", "")
                response_secret_data = {"username": username, "password": password}
                if password != "" and username != "":
                    get_secret = True
            elif (self.secret_type == "key" or self.secret_type == "generic") and ibm_secret_type == "arbitrary":
                payload = extracted_secret.get("payload", "")
                response_secret_data = {"key": payload}
                if payload != "":
                    get_secret = True
            elif (self.secret_type == "certificate" or self.secret_type == "generic") and ibm_secret_type == "imported_cert":
                certificate = extracted_secret.get("certificate", "")
                private_key = extracted_secret.get("private_key", "")
                response_secret_data["cert"] = certificate
                response_secret_data["key"] = private_key
                if certificate != "" or private_key != "":
                    get_secret = True
            elif self.secret_type == "generic" and ibm_secret_type == "kv":
                data = extracted_secret.get("data", {})
                response_secret_data = data
                if len(data) > 0:
                    get_secret = True
            # there is no matching type, so put all data into response
            elif self.secret_type == "generic":
                response_secret_data = extracted_secret
                get_secret = True


            if not get_secret:
                logException(self, "extractSecret()", FILE_NAME, "Failed to get secret content of IBM secret manager")
                return None, buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE

            response = {"secret": {}}
            if self.secret_type != "key":
                response["secret"][self.secret_type] = response_secret_data
            else:
                response["secret"] = response_secret_data

            if is_bulk:
                response[SECRET_URN] = self.secret_urn


            return response, None, None
        except Exception as err: 
            logException(self, "extractSecret()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_22900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
        