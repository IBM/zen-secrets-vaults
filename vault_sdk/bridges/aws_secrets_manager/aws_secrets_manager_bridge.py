import json
import base64
import datetime, hashlib, hmac 
import re
import os
import sys

# include parent paths, so the module can be imported
current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
parent = os.path.dirname(parent)
parent = os.path.dirname(parent)
sys.path.append(parent)

from vault_sdk.bridges_common.constants import *
from vault_sdk.bridges.aws_secrets_manager.constants import *
from vault_sdk.bridges.aws_secrets_manager.error_codes import COMPONENT_EXCEPTIONS
from vault_sdk.framework.utils import buildExceptionPayload, sendPostRequest, logException, logDebug, getCurrentFilename

FILE_NAME = getCurrentFilename(__file__)

class AWSSecretsManager(object):
    def __init__(self, secret_reference_metadata, secret_type, secret_urn, auth_string, transaction_id):
        self.vault_type = AWS_SECRETS_MANAGER
        self.secret_type = secret_type
        self.secret_reference_metadata = secret_reference_metadata
        self.auth_string = auth_string
        self.transaction_id = transaction_id
        self.secret_urn = secret_urn
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
                return buildExceptionPayload("vaultbridgesdk_e_20102", self, target), HTTP_NOT_FOUND_CODE
            
            self.secret_id = secret_id
            return None, None
        except Exception as err: 
            logException(self, "extractSecretReferenceMetadata()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
        

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
                return buildExceptionPayload("vaultbridgesdk_e_20200", self, target), HTTP_NOT_FOUND_CODE

            if secret_type not in SECRET_TYPES[AWS_SECRETS_MANAGER]:
                target = {"name": SECRET_REFERENCE_METADATA, "type": "query-param"}
                return buildExceptionPayload("vaultbridgesdk_e_20103", self, target), HTTP_NOT_FOUND_CODE

            self.secret_id = secret_id
            self.secret_urn = secret_urn
            self.secret_type = secret_type

            return None, None
        except Exception as err: 
            logException(self, "extractSecretReferenceMetadataBulk()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
        
# @extracts host, service, and region from the given AWS URL
    def extractFromVaultURL(self, url):
        try:
            missing_components = []
            if not url.startswith("https://"):
                logException(self, "extractSecretReferenceMetadataBulk()", FILE_NAME, INVALID_VAULT_URL_ERROR.format('https://'))
                return buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
            host = url[len("https://"):].strip().lower()

            components = host.split('.')

            service = components[0] if len(components) > 0 else None
            region = components[1] if len(components) > 1 else None

            if not host:
                missing_components.append("host")
            if not service:
                missing_components.append("service")
            if not region or not components[2].startswith('amazonaws'):
                missing_components.append("region")

            if missing_components:
                return buildExceptionPayload("vaultbridgesdk_e_20001", self), HTTP_NOT_FOUND_CODE
            self.host = host
            self.service = service
            self.region = region

            return None, None            

        except Exception as err: 
            logException(self, "extractFromVaultURL()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @returns {string} error message if any
    def extractFromVaultAuthHeader(self):
        try:
            decoded_auth_header = base64.b64decode(self.auth_string).decode('utf-8')
            
            auth_list = decoded_auth_header.split(";")
            if len(auth_list) < 3:
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildExceptionPayload("vaultbridgesdk_e_20001", self, target), HTTP_NOT_FOUND_CODE         
            self.auth = {}
            for item in auth_list:
                temp = item.split("=")
                if len(temp) < 2:
                    target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                    return buildExceptionPayload("vaultbridgesdk_e_20001", self, target), HTTP_NOT_FOUND_CODE
                self.auth[temp[0]] = temp[1]

            if self.auth.get(VAULT_URL, "") == "" or self.auth.get(AWS_ACCESS_KEY_ID, "") == "" or self.auth.get(AWS_SECRET_ACCESS_KEY, "") == "":
                target = {"name": VAULT_AUTH_HEADER, "type": "header"}
                return buildExceptionPayload("vaultbridgesdk_e_20002", self, target), HTTP_NOT_FOUND_CODE

            error, code = self.extractFromVaultURL(self.auth[VAULT_URL])
            if error is not None:
                return error, code
            return None, None
        except Exception as err: 
            logException(self, "extractFromVaultAuthHeader()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
        
    # Generates a HMAC signature for msg using the provided key
    def sign(self, key, msg):
        try:
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest(), None, None
        except Exception as err: 
            logException(self, "sign()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE

    # Generates an AWS V4 Signature using a set of HMAC signing steps provided by AWS
    def generateSignature(self, key, dateStamp, regionName, serviceName):
        try:
            kDate, error, code = self.sign(('AWS4' + key).encode('utf-8'), dateStamp)
            if error is not None:
                return None, error, code            
            kRegion, error, code = self.sign(kDate, regionName)
            if error is not None:
                return None, error, code
            kService, error, code = self.sign(kRegion, serviceName)
            if error is not None:
                return None, error, code
            kSigning, error, code = self.sign(kService, 'aws4_request')
            if error is not None:
                return None, error, code

            return kSigning, None, None
        except Exception as err: 
            logException(self, "generateSignature()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE     


    # @param {bool} is_bulk — true if this is a bulk request
    #
    # @returns {dict} extracted_secret - secret in python dict format
    # @returns {string} error message if any
    # @returns {number} status code
    def processRequestGetSecret(self, is_bulk=False):
        try:
            
            secret, error, code = self.getSecret()
            if error is not None:
                return None, error, code
            # return secret, None, None
            
            extracted_secret, error, code = self.extractSecret(secret, is_bulk)
            if error is not None:
                return None, error, code
            
            return extracted_secret, None, None
        except Exception as err: 
            logException(self, "processRequestGetSecret()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE

    # Generates hashed payload, timestamp and authorization_header 
    def generateHeaders(self, payload):
        try:

            t = datetime.datetime.utcnow()
            amzdate = t.strftime('%Y%m%dT%H%M%SZ')
            self.amzdate = amzdate
            datestamp = t.strftime('%Y%m%d')

            # Creating Canonical Request
            canonical_uri = '/' 
            canonical_querystring = ""
            method = 'POST'
            payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
            self.payload_hash = payload_hash

            canonical_headers = 'host:' + self.host + '\n' + 'x-amz-content-sha256:' + payload_hash + '\n' + 'x-amz-date:' + amzdate + '\n' + 'x-amz-target:secretsmanager.GetSecretValue' + '\n'
            signed_headers = 'host;x-amz-content-sha256;x-amz-date;x-amz-target'
            canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

            # Creating String to Sign
            algorithm = 'AWS4-HMAC-SHA256'
            credential_scope = datestamp + '/' + self.region + '/' + self.service + '/' + 'aws4_request'
            string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

            # Calculating Signature
            signing_key, error, code = self.generateSignature(self.auth[AWS_SECRET_ACCESS_KEY], datestamp, self.region, self.service)
            if error is not None:
                return error, code
            signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
            # Creating authorization header
            authorization_header = algorithm + ' ' + 'Credential=' + self.auth[AWS_ACCESS_KEY_ID] + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
            self.authorization_header = authorization_header
            return None, None

        except Exception as err: 
            logException(self, "generateHeaders()", FILE_NAME, str(err))
            return buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE


    # @returns {dict} extracted_secret - secret in python dict format
    # @returns {string} error message if any
    # @returns {number} status code 
    def getSecret(self):
        try:

            data = f'{{"SecretId": "{self.secret_id}"}}'

            error, code = self.generateHeaders(data)

            headers = {
                'x-amz-date': self.amzdate,
                'x-amz-content-sha256': self.payload_hash,
                'Authorization': self.authorization_header,
                'X-Amz-Target': 'secretsmanager.GetSecretValue',
                'Content-Type': 'application/x-amz-json-1.1'
            }

            logDebug(self, "getSecret()", FILE_NAME, "Sending request to get the secret")

            response = sendPostRequest(self.auth[VAULT_URL], headers, data)
            # return error if the request failed
            if response.status_code != HTTP_SUCCESS_CODE:
                logException(self, "getSecret()", FILE_NAME, f"{response.text} and status code {response.status_code} returned from {self.auth[VAULT_URL]}")
                return None, buildExceptionPayload("vaultbridgesdk_e_20500", self), HTTP_INTERNAL_SERVER_ERROR_CODE
            
            return response.text, None, None

        except Exception as err: 
            logException(self, "getSecret()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE


    # Format certificate and Secret to replace " " with "\n" for each new line
    def formatCertKeyValue(self, cert, key):
        try:
            pattern = r'((?:-{5}BEGIN.*?-{5})|(?:-{5}END.*?-{5}))| '

            def replacer(match):
                if match.group(1):
                    return match.group(1)
                return '\n'

            formatted_cert = re.sub(pattern, replacer, cert)
            formatted_key = re.sub(pattern, replacer, key)

            return formatted_cert, formatted_key, None, None
        
        except Exception as err:
            logException(self, "formatCertKeyValue()", FILE_NAME, str(err))
            return None, None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE

    # @param {string} secret — secret content in string
    # @param {bool} is_bulk — true if this is a bulk request
    #
    # @returns {dict} response - content of response
    # @returns {string} error message if any
    # @returns {number} status code
    def extractSecret(self, secret, is_bulk=False):
        try:
            logDebug(self, "extractSecret()", FILE_NAME, "Extracting secret data")
            
            get_secret = False
            secret_type = ""
            secret_data = json.loads(secret)
            secret_string = secret_data.get("SecretString", "")
            content_type = ""
            if secret_data.get("contentType", "") != "":
                content_type = secret_data.get("contentType")
            secret_type = self.secret_type.lower()
            response_secret_data = {}
            
            if secret_type == "credentials":
                creds_value = json.loads(secret_string)
                if not isinstance(creds_value, dict): 
                    logException(INVALID_JSON_FORMAT_ERROR)
                    return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
                username = creds_value.get("username", "")
                password = creds_value.get("password", "")
                response_secret_data = {"username": username, "password": password}
                
                if password and username:
                    get_secret = True

            elif secret_type == "key":
                key_value = json.loads(secret_string)
                if not isinstance(key_value, dict): 
                    logException(INVALID_JSON_FORMAT_ERROR)
                    return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
                key = key_value.get("key", "")
                response_secret_data = {"key": key}
                if key:
                    get_secret = True

            elif secret_type == "token":
                token_value = json.loads(secret_string)
                if not isinstance(token_value, dict): 
                    logException(INVALID_JSON_FORMAT_ERROR)
                    return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE
                token = token_value.get("token", "")
                response_secret_data = {"token": token}
                if token:
                    get_secret = True

            elif secret_type == "certificate":
                cert_value = json.loads(secret_string)
                cert = cert_value.get("certificate", "")
                k = cert_value.get("key", "")
                certificate, key, error, code = self.formatCertKeyValue(cert, k)
                if error is not None:
                    return None, error, code

                response_secret_data["cert"] = certificate
                response_secret_data["key"] = key
                if certificate or key:
                    get_secret = True

            elif secret_type == "generic":
                try:
                    # Try to parse the secret_string as JSON
                    response_secret_data = json.loads(secret_string)
                    get_secret = True
                except json.JSONDecodeError:
                    # If an error occurs, treat it as plaintext
                    response_secret_data = secret_string
                    get_secret = True

            if not get_secret:
                logException(f"failed to get secret content for secret content for secret_type {secret_type}")
                return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE

            response = {"secret": {}}
            if self.secret_type != "key" and self.secret_type != "token":
                response["secret"][self.secret_type] = response_secret_data
            else:
                response["secret"] = response_secret_data
            if is_bulk:
                response[SECRET_URN] = self.secret_urn

            return response, None, None
        except Exception as err:
            logException(self, "extractSecret()", FILE_NAME, str(err))
            return None, buildExceptionPayload("vaultbridgesdk_e_20900", self), HTTP_INTERNAL_SERVER_ERROR_CODE