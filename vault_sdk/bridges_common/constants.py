LOGGING_LEVEL_LIST = ["DEBUG", "INFO", "ERROR", "CRITICAL"]

# vault constants
IBM_SECRETS_MANAGER = "ibm-cloud-secrets-manager"
AWS_SECRETS_MANAGER = "aws-secrets-manager"
AZURE_KEY_VAULT = "azure-key-vault"

VAULT_TYPES = [IBM_SECRETS_MANAGER, AWS_SECRETS_MANAGER, AZURE_KEY_VAULT]
SECRET_TYPES = {
    IBM_SECRETS_MANAGER: ["credentials", "certificate", "generic", "key"],
    AWS_SECRETS_MANAGER: ["credentials", "certificate", "generic", "key", "token"],
    AZURE_KEY_VAULT: ["credentials", "certificate", "generic", "key"]
}

# requests constants
VAULT_URL = "vault_url"
SECRET_REFERENCE_METADATA = "secret_reference_metadata"
VAULT_TYPE = "vault_type"
SECRET_URN = "secret_urn"
SECRET_TYPE = "secret_type"
VAULT_AUTH_HEADER = "Vault-Auth"
TRANSACTION_ID_HEADER = "IBM-CPD-Transaction-ID"

# error message
ERROR_MISSING_VAULT_HEADER = "Missing vault connection information in VAULT-AUTH header"
ERROR_ESTABLISHING_CONNECTION = "Error while establishing connection with Vault providers IAM"
ERROR_TOKEN_NOT_RETURNED = "Token is not returned from ibm-secret-manager"
ERROR_INVALID_IAM_URL = "IAM URL is invalid"

# error codes
HTTP_SUCCESS_CODE = 200
HTTP_BAD_REQUEST_CODE = 400
HTTP_FORBIDDEN_CODE = 403
HTTP_NOT_FOUND_CODE = 404
HTTP_INTERNAL_SERVER_ERROR_CODE = 500

RETRY_ERROR_CODE_LIST = [500, 502, 503, 504]

INTERNAL_SERVER_ERROR = "Internal server error"

E_1000 = "vault_bridge_request_e_1000"
E_9000 = "vault_bridge_request_e_9000"



