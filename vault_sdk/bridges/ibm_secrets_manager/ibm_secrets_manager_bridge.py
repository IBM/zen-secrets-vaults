import json
import base64
import os
import sys

# include parent paths, so the module can be imported
current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)
parent = os.path.dirname(parent)
parent = os.path.dirname(parent)
sys.path.append(parent)

from ibm_secrets_manager.constants import *
from vault_sdk import caches
from vault_sdk.constants import *
from vault_sdk.utils import getCachedToken, sendGetRequest, sendPostRequest, buildErrorPayload

class IBMSecretManager(object):
    def __init__(self, secret_reference_metadata, secret_type, secret_urn, auth_string, transaction_id, is_validate="false"):
        self.vault_type = IBM_SECRETS_MANAGER
        self.secret_reference_metadata = secret_reference_metadata
        self.secret_type = secret_type
        self.secret_urn = secret_urn
        self.auth_string = auth_string
        self.transaction_id = transaction_id
        self.is_validate = is_validate
        self.secret_id = ""


    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    #
    # this function extract secret_id from request query param secret_reference_metadata
    def extractSecretReferenceMetadata(self, logging):
        try:
            decoded_secret_metadata = json.loads(base64.b64decode(self.secret_reference_metadata).decode('utf-8'))
            secret_id = decoded_secret_metadata.get(SECRET_ID, "")

            if secret_id == "":
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildErrorPayload(f"{self.transaction_id}: {ERROR_SECRET_ID_NOT_FOUND}", E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
            
            self.secret_id = secret_id
            return None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_urn}: Got error: {str(err)}")
            return buildErrorPayload(str(err), E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
        

    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    #
    # this function extract secret_id, secret_urn, and secret_type from request query param secret_reference_metadata
    def extractSecretReferenceMetadataBulk(self, logging):
        try:
            secret_urn = self.secret_reference_metadata.get(SECRET_URN, "")
            secret_id = self.secret_reference_metadata.get(SECRET_ID, "")
            secret_type = self.secret_reference_metadata.get(SECRET_TYPE, "")

            if secret_urn == "" or secret_id == "" or secret_type == "":
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildErrorPayload(f"{self.transaction_id} - {secret_urn}: secret type, secret id, and secret urn cannot be empty", E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE

            if secret_type not in SECRET_TYPES[IBM_SECRETS_MANAGER]:
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildErrorPayload(f"{self.transaction_id} - {secret_urn}: secret type {secret_type} is not supported", E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE

            self.secret_id = secret_id
            self.secret_urn = secret_urn
            self.secret_type = secret_type

            return None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_urn}: Got error: {str(err)}")
            return buildErrorPayload(str(err), E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
    
    

    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    def extractFromVaultAuthHeader(self, logging):
        try:
            decoded_auth_header = base64.b64decode(self.auth_string).decode('utf-8')

            auth_list = decoded_auth_header.split(";")
            if len(auth_list) < 3:
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildErrorPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
            
            self.auth = {}
            for item in auth_list:
                temp = item.split("=")
                if len(temp) < 2:
                     target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                     return buildErrorPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
                self.auth[temp[0]] = temp[1]

            if self.auth.get(VAULT_URL, "") == "" or  self.auth.get(IAM_URL, "") == "" or self.auth.get(API_KEY, "") == "":
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildErrorPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE

            return None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_urn}: Got error in function extractFromVaultAuthHeader(): {str(err)}")
            return buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {logging} logging — python logging handler
    # @param {bool} is_bulk — true if this is a bulk request
    #
    # @returns {dict} extracted_secret - secret in python dict format
    # @returns {string} error message if any
    # @returns {number} status code
    def processRequestGetSecret(self, logging, is_bulk=False):
        try:
            error, code = self.getAccessToken(logging)
            if error is not None:
                return None, error, code
            
            secret, error, code = self.getSecret(logging)
            if error is not None:
                return None, error, code
            
            extracted_secret, error, code = self.extractSecret(secret, logging, is_bulk)
            if error is not None:
                return None, error, code
            
            return extracted_secret, None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_urn}: Got error in function processRequestGetSecret(): {str(err)}")
            return buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    # @returns {number} status code
    def getAccessToken(self, logging):
        try:
            # get cached token and check if it is expired
            cached_token = getCachedToken(self, logging)
            if cached_token != "":
                return None, None

            # if token is expired, then send request to get a new token
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
            data = {
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self.auth[API_KEY]
            }

            response = sendPostRequest(self.auth[IAM_URL], headers, data, logging)
            # return error if the request failed
            if response.status_code != HTTP_SUCCESS_CODE:
                logging.error(f"Error {response.text} and status code {response.status_code} returned from {self.auth[IAM_URL]}")
                return buildErrorPayload(ERROR_ESTABLISHING_CONNECTION, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE
            
            
            data = json.loads(response.text)

            if "access_token" not in data or "expiration" not in data:
                return buildErrorPayload(ERROR_TOKEN_NOT_RETURNED, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE

            # store token to cache
            caches.TOKEN[self.vault_type][self.auth[API_KEY]] = {}
            caches.TOKEN[self.vault_type][self.auth[API_KEY]]["token"] = data["access_token"]
            caches.TOKEN[self.vault_type][self.auth[API_KEY]]["expiration"] = data["expiration"]

            return None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_urn}: Got error in function getAccessToken(): {str(err)}")
            return buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {logging} logging — python logging handler
    #
    # @returns {string} response body
    # @returns {string} error message if any
    # @returns {number} status code    
    def getSecret(self, logging):
        try:
            logging.debug(f"{self.transaction_id} - {self.secret_urn}: Sending request to get the secret")
            headers = {
                "Authorization": "Bearer " + caches.TOKEN[self.vault_type][self.auth[API_KEY]]["token"],
                "Accept": "application/json"
            }

            response = sendGetRequest(self.auth[VAULT_URL]+"/"+self.secret_id, headers, None, logging)
            if response.status_code != HTTP_SUCCESS_CODE:
                logging.error(f"Error {response.text} and status code {response.status_code} returned from {self.auth[VAULT_URL]}")
                return None, buildErrorPayload("Error while establishing connection with Vault providers", E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE

            return response.text, None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_urn}: Got error in function getSecret(): {str(err)}")
            return None, buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE
    

    # @param {string} secret — secret content in string
    # @param {logging} logging — python logging handler
    # @param {bool} is_bulk — true if this is a bulk request
    #
    # @returns {dict} response - content of response
    # @returns {string} error message if any
    # @returns {number} status code
    def extractSecret(self, secret, logging, is_bulk=False):
        try:
            logging.debug(f"{self.transaction_id} - {self.secret_urn}: Extracting secret data")
            extracted_secret = json.loads(secret)
            ibm_secret_type = extracted_secret[SECRET_TYPE] 

            response_secret_data = {}
            get_secret = False

            if self.is_validate == "true":
                response_secret_data = extracted_secret
                get_secret = True
            elif self.secret_type == "credentials":
                if ibm_secret_type != "username_password":
                    return None, buildErrorPayload(self.extractErrorString(self.secret_type, ibm_secret_type), E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
                username = extracted_secret.get("username", "")
                password = extracted_secret.get("password", "")
                response_secret_data = {"username": username, "password": password}
                if password != "" and username != "":
                    get_secret = True
            elif self.secret_type == "key":
                if ibm_secret_type != "arbitrary":
                    return None, buildErrorPayload(self.extractErrorString(self.secret_type, ibm_secret_type), E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
                payload = extracted_secret.get("payload", "")
                response_secret_data = payload
                if payload != "":
                    get_secret = True
            elif self.secret_type == "certificate":
                if ibm_secret_type != "imported_cert":
                    return None, buildErrorPayload(self.extractErrorString(self.secret_type, ibm_secret_type), E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
                certificate = extracted_secret.get("certificate", "")
                private_key = extracted_secret.get("private_key", "")
                response_secret_data["cert"] = certificate
                response_secret_data["key"] = private_key
                if certificate != "" or private_key != "":
                    get_secret = True
            elif self.secret_type == "generic":
                if ibm_secret_type != "kv":
                    return None, buildErrorPayload(self.extractErrorString(self.secret_type, ibm_secret_type), E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
                response_secret_data = extracted_secret
                get_secret = True

            if not get_secret:
                logging.error(f"{self.transaction_id} - {self.secret_urn}: failed to get secret content of IBM secret manager")
                return None, buildErrorPayload("Failed to get secret content of IBM secret manager", E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE

            response = {"secret": {}}
            response["secret"][self.secret_type] = response_secret_data
            if is_bulk:
                response[SECRET_URN] = self.secret_urn


            return response, None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_urn}: Got error in function extractSecret(): {str(err)}")
            return None, buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE
        
        
    def extractErrorString(self, secret_type, ibm_secret_type):
        return f"Requested secret_type {secret_type} does not match with mapped vault secret_type {ibm_secret_type}"

