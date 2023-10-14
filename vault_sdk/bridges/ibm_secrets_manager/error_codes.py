# This name will appears exception_info.md
COMPONENT_NAME = "IBM Cloud Secrets Manager"
COMPONENT_TYPE = "Vault Bridge"

COMPONENT_EXCEPTIONS = {
    "vaultbridgesdk_e_22001" : {
        "code" : "vaultbridgesdk_e_22001",
        "http_status_code" : 404,
        "message" : "Received insufficient vault auth information, ensure all required attributes are passed in the vault auth header.",
        "reason" : "Expected 2 attributes included in the vault authentication however received less than 2.",
        "action" : "Ensure all required attributes VAULT_URL and API_KEY are passed in the vault auth header."
    },
    "vaultbridgesdk_e_22002" : {
        "code" : "vaultbridgesdk_e_22002",
        "http_status_code" : 404,
        "message" : "Received incomplete vault auth information, ensure attributes are passed in the vault auth header does not have empty value.",
        "reason" : "Value of the attributes passed in the vault auth header has empty values.",
        "action" : "Ensure vault auth header attributes VAULT_URL and API_KEY do not have empty values."
    },
    "vaultbridgesdk_e_22101" : {
        "code" : "vaultbridgesdk_e_22101",
        "http_status_code" : 404,
        "message" : "Malformed secret metadata passed in the query param secret_reference_metadata, ensure secret metadata is valid json.",
        "reason" : "Secret metadata passed in the query param secret_reference_metadata is not valid json.",
        "action" : "Ensure secret metadata passed in the query param secret_reference_metadata is valid json with key secret_id."
    },
    "vaultbridgesdk_e_22102" : {
        "code" : "vaultbridgesdk_e_22102",
        "http_status_code" : 404,
        "message" : "Missing secret_id, ensure secret metadata json includes key `secret_id`.",
        "reason" : "secret_id is missing from the secret metadata json.",
        "action" : "Ensure secret metadata json includes secret_id key."
    },
    "vaultbridgesdk_e_22103" : {
        "code" : "vaultbridgesdk_e_22103",
        "http_status_code" : 404,
        "message" : "The Cloud Pak secret type is mismatched with vault secret type, ensure secret type on CloudPak aligns / matches with secret type on the vault.",
        "reason" : "Secret type on the Cloud Pak does not align / match with the secret type on the vault.",
        "action" : "Ensure secret type on the Cloud Pak aligns / matches with secret type on the vault."
    },
    "vaultbridgesdk_e_22200" : {
        "code" : "vaultbridgesdk_e_22200",
        "http_status_code" : 404,
        "message" : "Bulk secret - The secret reference data is missing, ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata.",
        "reason" : "The query parameter secret_reference_metadata is not specified.",
        "action" : "Ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata."
    },
    "vaultbridgesdk_e_22201" : {
        "code" : "vaultbridgesdk_e_22201",
        "http_status_code" : 404,
        "message" : "Bulk secret - secret reference data is malformed and not a valid json, ensure secret metadata is a valid json.",
        "reason" : "Secret metadata is not a valid json",
        "action" : "Ensure secret metadata is a valid json array with keys secret_type, secret_id, and secret_urn."
    },
    "vaultbridgesdk_e_22500" : {
        "code" : "vaultbridgesdk_e_22500",
        "http_status_code" : 500,
        "message" : "Received exception from the vault, check vault bridge log for further details.",
        "reason" : "Received exception from the vault when processing the request.",
        "action" : "Check the vault bridge logs for the further error details."
    },
    "vaultbridgesdk_e_22501" : {
        "code" : "vaultbridgesdk_e_22501",
        "http_status_code" : 500,
        "message" : "Encountered internal exception while requesting authentication token from the IAM, check the vault bridge logs for the further details.",
        "reason" : "Encountered internal exception while requesting vault token",
        "action" : "Check the vault bridge logs for the further error details."
    },
    "vaultbridgesdk_e_22900" : {
        "code" : "vaultbridgesdk_e_22900",
        "http_status_code" : 500,
        "message" : "Encountered internal exception while processing the request, check the vault bridge logs for the further details.",
        "reason" : "Encountered internal exception while processing the request.",
        "action" : "Check the vault bridge logs for the further error details."
    }
}