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

from vault_sdk.bridges_common.constants import *
from vault_sdk.bridges.azure_key_vault.constants import *
from vault_sdk.framework.utils import getCachedToken, saveTokenInCache, buildExceptionPayload, sendGetRequest, sendPostRequest, logException, logDebug, getCurrentFilename

FILE_NAME = getCurrentFilename(__file__)

class AzureKeyVault(object):
    def __init__(self, secret_reference_metadata, secret_type, secret_urn, auth_string, transaction_id):
        self.vault_type = AZURE_KEY_VAULT
        self.secret_type = secret_type
        self.secret_reference_metadata = secret_reference_metadata
        self.auth_string = auth_string
        self.transaction_id = transaction_id
        self.secret_urn = secret_urn


    # @returns {string} error message if any
    #
    # this function extract secret_name from request query param secret_reference_metadata
    def extractSecretReferenceMetadata(self):
        try:
            decoded_secret_metadata = json.loads(base64.b64decode(self.secret_reference_metadata).decode('utf-8'))
            secret_name = decoded_secret_metadata.get(SECRET_NAME, "")

            if secret_name == "":
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildExceptionPayload(f"{ERROR_SECRET_NAME_NOT_FOUND}", E_1000, self, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
            
            self.secret_name = secret_name
            return None, None
        except Exception as err: 
            logException(self, "extractSecretReferenceMetadata()", FILE_NAME, str(err))
            return buildExceptionPayload(str(err), E_1000, self, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE


    # @returns {string} error message if any
    #
    # this function extract secret_name, secret_urn, and secret_type from request query param secret_reference_metadata
    def extractSecretReferenceMetadataBulk(self):
        try:
            secret_urn = self.secret_reference_metadata.get(SECRET_URN, "")
            secret_name = self.secret_reference_metadata.get(SECRET_NAME, "")
            secret_type = self.secret_reference_metadata.get(SECRET_TYPE, "")

            if secret_urn == "" or secret_name == "" or secret_type == "":
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildExceptionPayload(f"{secret_urn}: secret type, secret name, and secret urn cannot be empty", E_1000, self, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE

            if secret_type not in SECRET_TYPES[AZURE_KEY_VAULT]:
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildExceptionPayload(f"{secret_urn}: secret type {secret_type} is not supported", E_1000, self, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE

            self.secret_name = secret_name
            self.secret_urn = secret_urn
            self.secret_type = secret_type

            return None, None
        except Exception as err: 
            logException(self, "extractSecretReferenceMetadataBulk()", FILE_NAME, str(err))
            return buildExceptionPayload(str(err), E_1000, self, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE


    # @returns {string} error message if any
    def extractFromVaultAuthHeader(self):
        try:
            decoded_auth_header = base64.b64decode(self.auth_string).decode('utf-8')
            
            auth_list = decoded_auth_header.split(";")
            if len(auth_list) < 4:
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildExceptionPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE           
            self.auth = {}
            for item in auth_list:
                temp = item.split("=")
                if len(temp) < 2:
                    target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                    return buildExceptionPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
                self.auth[temp[0]] = temp[1]

            if self.auth.get(VAULT_URL, "") == "" or self.auth.get(TENANT_ID, "") == "" or self.auth.get(CLIENT_ID, "") == "" or self.auth.get(CLIENT_SECRET, "") == "":
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildExceptionPayload(ERROR_MISSING_VAULT_HEADER, E_1000, self, HTTP_BAD_REQUEST_CODE, target), HTTP_BAD_REQUEST_CODE
            
            self.auth[AZURE_IAM_URL] = os.environ.get('AZURE_IAM_URL', DEFAULT_AZURE_IAM_URL)
            self.cache_key = self.auth[CLIENT_ID] + "~" + self.auth[CLIENT_SECRET] + "~" +self.auth[TENANT_ID]

            return None, None
        except Exception as err: 
            logException(self, "extractFromVaultAuthHeader()", FILE_NAME, str(err))
            return buildExceptionPayload(INTERNAL_SERVER_ERROR, E_9000, self, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


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
            return buildExceptionPayload(INTERNAL_SERVER_ERROR, E_9000, self, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @returns {string} error message if any
    # @returns {number} status code
    def getAccessToken(self):
        try:
            cached_token = getCachedToken(AZURE_KEY_VAULT, self.cache_key, self.transaction_id)
            if cached_token != "":
                return cached_token, None, None

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
            
            response = sendPostRequest(iam_url, headers, data)
            # return error if the request failed
            if response.status_code != HTTP_SUCCESS_CODE:
                logException(self, "getAccessToken()", FILE_NAME, f"Error {response.text} and status code {response.status_code} returned from {iam_url}")
                return None, buildExceptionPayload(ERROR_ESTABLISHING_CONNECTION, E_9000, self, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE
            data = json.loads(response.text)

            if "access_token" not in data or "expires_in" not in data:
                return None, buildExceptionPayload(ERROR_TOKEN_NOT_RETURNED, E_1000, self, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
            
            # store token to cache
            expires_dur = data.get("expires_in", 0) 
            expiration = (datetime.now() + timedelta(seconds=expires_dur)).timestamp()
            token = {"token": data["access_token"], "expiration": expiration}
            saveTokenInCache(AZURE_KEY_VAULT, self.cache_key, token, self.transaction_id)

            return data["access_token"], None, None
        except Exception as err: 
            logException(self, "getAccessToken()", FILE_NAME, str(err))
            return None, buildExceptionPayload(INTERNAL_SERVER_ERROR, E_9000, self, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @returns {dict} extracted_secret - secret in python dict format
    # @returns {string} error message if any
    # @returns {number} status code 
    def getSecret(self, token):
        try:
            logDebug(self, "getSecret()", FILE_NAME, "Sending request to get the secret")
            headers = {
                "Authorization": "Bearer " + token,
                "Accept": "application/json"
            }

            response = sendGetRequest(self.auth[VAULT_URL]+"/secrets/"+self.secret_name+"?api-version=7.3", headers, None)
            if response.status_code != HTTP_SUCCESS_CODE:
                logException(self, "getSecret()", FILE_NAME, f"{response.text} and status code {response.status_code} returned from {self.auth[VAULT_URL]}")
                return None, buildExceptionPayload("Error while establishing connection with Vault providers", E_9000, self, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE

            return response.text, None, None
        except Exception as err: 
            logException(self, "getSecret()", FILE_NAME, str(err))
            return None, buildExceptionPayload(INTERNAL_SERVER_ERROR, E_9000, self, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE

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
    # @param {bool} is_bulk — true if this is a bulk request
    #
    # @returns {dict} response - content of response
    # @returns {string} error message if any
    # @returns {number} status code
    def extractSecret(self, secret, is_bulk=False):
        try:
            logDebug(self, "getSecret()", FILE_NAME, "Extracting secret data")
            
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
                return None, buildExceptionPayload(UNSUPPORTED_TYPE_PKCS12, E_1000, self, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
            
            if secret_type == "credentials":
                creds_value = json.loads(secret_value)
                if not isinstance(creds_value, dict): 
                    return None, buildExceptionPayload(INVALID_JSON_FORMAT_ERROR, E_1000, self, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE
                username = creds_value.get("username", "")
                password = creds_value.get("password", "")
                response_secret_data = {"username": username, "password": password}
                
                if password and username:
                    get_secret = True

            elif secret_type == "key":
                key_value = secret_value
                response_secret_data = {"key": key_value}
                if key_value:
                    get_secret = True

            elif secret_type == "certificate":
                certificate, key = self.extractCertKeyValue(secret_value)

                response_secret_data["cert"] = certificate
                response_secret_data["key"] = key
                if certificate or key:
                    get_secret = True

            elif secret_type == "token":
                token_value = secret_value
                response_secret_data = {"token": token_value}
                if token_value:
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
                return None, buildExceptionPayload(f"failed to get secret content for secret content for secret_type {secret_type}", E_1000, self, HTTP_BAD_REQUEST_CODE), HTTP_BAD_REQUEST_CODE

            response = {"secret": {}}
            response["secret"] = response_secret_data
            if is_bulk:
                response[SECRET_URN] = self.secret_urn

            return response, None, None
        except Exception as err:
            logException(self, "extractSecret()", FILE_NAME, str(err))
            return None, buildExceptionPayload(INTERNAL_SERVER_ERROR, E_9000, self, HTTP_INTERNAL_SERVER_ERROR_CODE), HTTP_INTERNAL_SERVER_ERROR_CODE