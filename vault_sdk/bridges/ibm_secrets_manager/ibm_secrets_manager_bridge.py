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

from vault_sdk import caches
from vault_sdk.constants import *
from vault_sdk.utils import getCachedToken, sendGetRequest, sendPostRequest, buildErrorDict

class IBMSecretManager(object):
    def __init__(self, secret_metadata, secret_type, secret_urn, auth_string):
        self.vault_type = IBM_SECRETS_MANAGER
        self.secret_metadata = base64.b64decode(secret_metadata).decode('utf-8')
        self.secret_type = secret_type
        self.secret_urn = secret_urn
        self.auth_string = auth_string


    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    def extractFromVaultAuthHeader(self, logging):
        try:
            decoded_auth_header = base64.b64decode(self.auth_string).decode('utf-8')

            auth_list = decoded_auth_header.split(";")
            if len(auth_list) < 3:
                return buildErrorDict("Missing value in VAULT-AUTH header"), HTTP_BAD_REQUEST_CODE
            
            self.auth = {}
            for item in auth_list:
                temp = item.split("=")
                if len(temp) < 2:
                     return buildErrorDict("Missing value in VAULT-AUTH header"), HTTP_BAD_REQUEST_CODE
                self.auth[temp[0]] = temp[1]

            if self.auth.get(VAULT_URL, "") == "" or  self.auth.get(IAM_URL, "") == "" or self.auth.get(API_KEY, "") == "":
                return buildErrorDict("Missing value in VAULT-AUTH header"), HTTP_BAD_REQUEST_CODE

            
            return None, None
        except Exception as err: 
            logging.error(f"{self.secret_urn}: Got error in function extractFromVaultAuthHeader(): {str(err)}")
            return buildErrorDict(INTERNAL_SERVER_ERROR), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {logging} logging — python logging handler
    #
    # @returns {dict} extracted_secret - secret in python dict format
    # @returns {string} error message if any
    # @returns {number} status code
    def processRequestGetSecret(self, logging):
        try:
            error, code = self.getAccessToken(logging)
            if error is not None:
                return None, error, code
            
            secret, error, code = self.getSecret(logging)
            if error is not None:
                return None, error, code
            
            extracted_secret, error, code = self.extractSecret(secret, logging)
            if error is not None:
                return None, error, code
            
            return extracted_secret, None, None
        except Exception as err: 
            logging.error(f"{self.secret_urn}: Got error in function processRequestGetSecret(): {str(err)}")
            return buildErrorDict(INTERNAL_SERVER_ERROR), HTTP_INTERNAL_SERVER_ERROR_CODE


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
                return response.text, response.status_code
            
            data = json.loads(response.text)

            if "access_token" not in data or "expiration" not in data:
                return buildErrorDict("Token is not returned from ibm-secret-manager"), HTTP_NOT_FOUND_CODE

            # store token to cache
            caches.TOKEN[self.vault_type][self.auth[API_KEY]] = {}
            caches.TOKEN[self.vault_type][self.auth[API_KEY]]["token"] = data["access_token"]
            caches.TOKEN[self.vault_type][self.auth[API_KEY]]["expiration"] = data["expiration"]

            return None, None
        except Exception as err: 
            logging.error(f"{self.secret_urn}: Got error in function getAccessToken(): {str(err)}")
            return buildErrorDict(INTERNAL_SERVER_ERROR), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {logging} logging — python logging handler
    #
    # @returns {string} response body
    # @returns {string} error message if any
    # @returns {number} status code    
    def getSecret(self, logging):
        try:
            logging.debug(f"{self.secret_urn}: Sending request to get the secret")
            headers = {
                "Authorization": "Bearer " + caches.TOKEN[self.vault_type][self.auth[API_KEY]]["token"],
                "Accept": "application/json"
            }

            response = sendGetRequest(self.auth[VAULT_URL]+"/"+self.secret_metadata, headers, None, logging)
            if response.status_code != HTTP_SUCCESS_CODE:
                return None, response.text, response.status_code

            return response.text, None, None
        except Exception as err: 
            logging.error(f"{self.secret_urn}: Got error in function getSecret(): {str(err)}")
            return None, buildErrorDict(INTERNAL_SERVER_ERROR), HTTP_INTERNAL_SERVER_ERROR_CODE
    

    # @param {string} secret — secret content in string
    # @param {logging} logging — python logging handler
    #
    # @returns {dict} response - content of response
    # @returns {string} error message if any
    # @returns {number} status code
    def extractSecret(self, secret, logging):
        try:
            logging.debug(f"{self.secret_urn}: Extracting secret data")
            extracted_secret = json.loads(secret)
            ibm_secret_type = extracted_secret["secret_type"] 

            response_secret_data = {}
            get_secret = False

            if self.secret_type == "credentials":
                if ibm_secret_type != "username_password":
                    return None, buildErrorDict(self.extractErrorString(self.secret_type, ibm_secret_type)), HTTP_BAD_REQUEST_CODE
                username = extracted_secret.get("username", "")
                password = extracted_secret.get("password", "")
                response_secret_data = {"username": username, "password": password}
                if password != "" and username != "":
                    get_secret = True
            elif self.secret_type == "key":
                if ibm_secret_type != "arbitrary":
                    return None, buildErrorDict(self.extractErrorString(self.secret_type, ibm_secret_type)), HTTP_BAD_REQUEST_CODE
                payload = extracted_secret.get("payload", "")
                response_secret_data = payload
                if payload != "":
                    get_secret = True
            elif self.secret_type == "certificate":
                if ibm_secret_type != "imported_cert":
                    return None, buildErrorDict(self.extractErrorString(self.secret_type, ibm_secret_type)), HTTP_BAD_REQUEST_CODE
                certificate = extracted_secret.get("certificate", "")
                private_key = extracted_secret.get("private_key", "")
                response_secret_data["cert"] = certificate
                response_secret_data["key"] = private_key
                if certificate != "" or private_key != "":
                    get_secret = True
            elif self.secret_type == "generic":
                if ibm_secret_type != "kv":
                    return None, buildErrorDict(self.extractErrorString(self.secret_type, ibm_secret_type)), HTTP_BAD_REQUEST_CODE
                response_secret_data = extracted_secret
                get_secret = True

            if not get_secret:
                logging.error(f"{self.secret_urn}: failed to get secret content")
                return None, buildErrorDict("Failed to get secret content"), HTTP_BAD_REQUEST_CODE

            response = {"secret": {}}
            response["secret"][self.secret_type] = response_secret_data

            return response, None, None
        except Exception as err: 
            logging.error(f"{self.secret_urn}: Got error in function extractSecret(): {str(err)}")
            return None, buildErrorDict(INTERNAL_SERVER_ERROR), HTTP_INTERNAL_SERVER_ERROR_CODE
        
        
    def extractErrorString(secret_type, ibm_secret_type):
        return f"Requested secret_type {secret_type} does not match with mapped vault secret_type {ibm_secret_type}"

