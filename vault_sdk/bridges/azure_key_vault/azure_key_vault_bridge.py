import json
import base64
import os
import sys
from datetime import datetime, timedelta

# include parent paths, so the module can be imported
current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
parent = os.path.dirname(parent)
parent = os.path.dirname(parent)
sys.path.append(parent)

from vault_sdk import caches
from vault_sdk.constants import *
from vault_sdk.bridges.azure_key_vault.constants import *
from vault_sdk.utils import getCachedToken, buildErrorPayload, sendGetRequest, sendPostRequest

class AzureKeyVault(object):
    def __init__(self, secret_reference_metadata, secret_type, secret_urn, auth_string, transaction_id):
        self.vault_type = AZURE_KEY_VAULT
        self.secret_type = secret_type
        self.secret_reference_metadata = secret_reference_metadata
        self.auth_string = auth_string
        self.transaction_id = transaction_id

    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    #
    # this function extract secret_name from request query param secret_reference_metadata
    def extractSecretReferenceMetadata(self, logging):
        try:
            decoded_secret_metadata = json.loads(base64.b64decode(self.secret_reference_metadata).decode('utf-8'))
            secret_name = decoded_secret_metadata.get(SECRET_NAME, "")

            if secret_name == "":
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildErrorPayload(f"{self.transaction_id}: {ERROR_SECRET_NAME_NOT_FOUND}", E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
            
            self.secret_name = secret_name
            return None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_name}: Got error: {str(err)}")
            return buildErrorPayload(str(err), E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE

    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    def extractFromVaultAuthHeader(self, logging):
        try:
            decoded_auth_header = base64.b64decode(self.auth_string).decode('utf-8')
            
            auth_list = decoded_auth_header.split(";")
            if len(auth_list) < 4:
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildErrorPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE           
            self.auth = {}
            for item in auth_list:
                temp = item.split("=")
                if len(temp) < 2:
                    target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                    return buildErrorPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
                self.auth[temp[0]] = temp[1]

            if self.auth.get(VAULT_URL, "") == "" or self.auth.get(TENANT_ID, "") == "" or self.auth.get(CLIENT_ID, "") == "" or self.auth.get(CLIENT_SECRET, "") == "":
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildErrorPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
            
            self.auth[AZURE_IAM_URL] = os.environ.get('AZURE_IAM_URL', DEFAULT_AZURE_IAM_URL)

            return None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_name}: Got error in function extractFromVaultAuthHeader(): {str(err)}")
            return buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


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
            logging.error(f"{self.transaction_id} - {self.secret_name}: Got error in function processRequestGetSecret(): {str(err)}")
            return buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {logging} logging — python logging handler
    #
    # @returns {string} error message if any
    # @returns {number} status code
    def getAccessToken(self, logging):
        try:
            logging.debug(f"{self.secret_name}: getCachedToken called")
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
                "client_id": self.auth[CLIENT_ID],
                "client_secret": self.auth[CLIENT_SECRET],
                "scope": "https://vault.azure.net/.default",
                "grant_type": "client_credentials"
            }

            iam_url = f"{self.auth[AZURE_IAM_URL]}/{self.auth[TENANT_ID]}/oauth2/v2.0/token"
            
            response = sendPostRequest(iam_url, headers, data, logging)
            # return error if the request failed
            if response.status_code != HTTP_SUCCESS_CODE:
                logging.error(f"{self.transaction_id} - {self.secret_name}: Error {response.text} and status code {response.status_code} returned from {iam_url}")
                return buildErrorPayload(ERROR_ESTABLISHING_CONNECTION, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE
            data = json.loads(response.text)

            if "access_token" not in data or "expires_in" not in data:
                return buildErrorPayload(ERROR_TOKEN_NOT_RETURNED, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
            
            expires_dur = data.get("expires_in", 0) 
            expiration = (datetime.now() + timedelta(seconds=expires_dur)).timestamp()

            # store token to cache
            caches.TOKEN[self.vault_type][self.auth[CLIENT_ID]] = {}
            caches.TOKEN[self.vault_type][self.auth[CLIENT_ID]]["token"] = data["access_token"]
            caches.TOKEN[self.vault_type][self.auth[CLIENT_ID]]["expiration"] = expiration

            return None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_name}: Got error in function getAccessToken(): {str(err)}")
            return buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @param {logging} logging — python logging handler
    #
    # @returns {dict} extracted_secret - secret in python dict format
    # @returns {string} error message if any
    # @returns {number} status code 
    def getSecret(self, logging):
        try:
            logging.debug(f"{self.secret_name}: Sending request to get the secret")
            headers = {
                "Authorization": "Bearer " + caches.TOKEN[self.vault_type][self.auth[CLIENT_ID]]["token"],
                "Accept": "application/json"
            }

            response = sendGetRequest(self.auth[VAULT_URL]+"/secrets/"+self.secret_name+"?api-version=7.3", headers, None, logging)
            if response.status_code != HTTP_SUCCESS_CODE:
                logging.error(f"{self.transaction_id} - {self.secret_name}:Error {response.text} and status code {response.status_code} returned from {self.auth[VAULT_URL]}")
                return None, buildErrorPayload("Error while establishing connection with Vault providers", E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE

            return response.text, None, None
        except Exception as err: 
            logging.error(f"{self.transaction_id} - {self.secret_name}: Got error in function getSecret(): {str(err)}")
            return None, buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE

    # Return certificate and Secret value from the input_string
    def extractCertKeyValue(self, input_string):

        input_string = input_string.replace(" ", "")

        cert_value = ""
        key_value = ""

        lines = input_string.split('\n')

        is_cert = False
        is_key = False

        for line in lines:
            line = line.strip()  
            if line.startswith("cert="):
                is_cert = True
                is_key = False
                cert_value += line.replace("cert=", "").replace("certificate =", "") + "\n"
            elif line.startswith("key="):
                is_cert = False
                is_key = True
                key_value += line.replace("key=", "") + "\n"
            elif is_cert:
                cert_value += line + "\n"
            elif is_key:
                key_value += line + "\n"

        return cert_value, key_value

    # @param {string} secret — secret content in string
    # @param {logging} logging — python logging handler
    #
    # @returns {dict} response - content of response
    # @returns {string} error message if any
    # @returns {number} status code
    def extractSecret(self, secret, logging):
        try:
            logging.debug(f"{self.secret_name}: Extracting secret data")
            
            get_secret = False
            secret_type = ""
            secret_data = json.loads(secret)
            secret_value = secret_data.get("value", "")
            content_type = ""
            if secret_data.get("contentType", "") != "":
                content_type = secret_data.get("contentType")
            pkcs12 = "application/x-pkcs12"
            secret_type = self.secret_type.lower()
            response_secret_data = {}
            if content_type == pkcs12:
                return None, buildErrorPayload(UNSUPPORTED_TYPE_PKCS12, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
            
            if secret_type == "credentials":
                creds_value = json.loads(secret_value)
                if not isinstance(creds_value, dict): 
                    return None, buildErrorPayload(INVALID_JSON_FORMAT_ERROR, E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
                username = creds_value.get("username", "")
                password = creds_value.get("password", "")
                response_secret_data = {"username": username, "password": password}
                
                if password and username:
                    get_secret = True

            elif secret_type == "key":
                key_value = secret_value
                response_secret_data = key_value
                if key_value:
                    get_secret = True

            elif secret_type == "certificate":
                certificate, key = self.extractCertKeyValue(secret_value)

                response_secret_data["cert"] = certificate
                response_secret_data["key"] = key
                if certificate or key:
                    get_secret = True

            elif secret_type == "generic":
                try:
                    # Try to parse the secret_value as JSON
                    response_secret_data = json.loads(secret_value)
                    get_secret = True
                except json.JSONDecodeError:
                    # If an error occurs, treat it as plaintext
                    response_secret_data = secret_value
                    get_secret = True

            if not get_secret:
                return None, buildErrorPayload(f"failed to get secret content for secret content for secret_type {secret_type}", E_1000, self.transaction_id, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE

            response = {"secret": {}}
            response["secret"][secret_type] = response_secret_data

            return response, None, None
        except Exception as err:
            logging.error(f"{self.transaction_id} - {self.secret_name}: Got error in function extractSecret(): {str(err)}")
            return None, buildErrorPayload(INTERNAL_SERVER_ERROR, E_9000, self.transaction_id, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE