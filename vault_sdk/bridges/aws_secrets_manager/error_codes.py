# This name will appears exception_info.md
VAULT_TYPE = "AWS Secrets Manager"

VAULT_BRIDGE_EXCEPTIONS = {
    "vaultbridgesdk_e_20001" : {
        "code" : "vaultbridgesdk_e_20001",
        "http_status_code" : 404,
        "message" : "Received insufficient vault auth information, ensure all required attributes are passed in the vault auth header.",
        "reason" : "Expected 2 attributes included in the vault authentication however received less than 2.",
        "action" : "Ensure all required attributes VAULT_URL, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY are passed in the vault auth header."
    },
    "vaultbridgesdk_e_20002" : {
        "code" : "vaultbridgesdk_e_20002",
        "http_status_code" : 404,
        "message" : "Received incomplete vault auth information, ensure attributes are passed in the vault auth header does not have empty value.",
        "reason" : "Value of the attributes passed in the vault auth header has empty values.",
        "action" : "Ensure vault auth header attributes VAULT_URL, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY do not have empty values."
    },
    "vaultbridgesdk_e_20101" : {
        "code" : "vaultbridgesdk_e_20101",
        "http_status_code" : 404,
        "message" : "Malformed secret metadata passed in the query param secret_reference_metadata, ensure secret metadata is valid json.",
        "reason" : "Secret metadata passed in the query param secret_reference_metadata is not valid json.",
        "action" : "Ensure secret metadata passed in the query param secret_reference_metadata is valid json with key secret_id."
    },
    "vaultbridgesdk_e_20102" : {
        "code" : "vaultbridgesdk_e_20102",
        "http_status_code" : 404,
        "message" : "Missing secret_id, ensure secret metadata json includes key `secret_id`.",
        "reason" : "secret_id is missing from the secret metadata json.",
        "action" : "Ensure secret metadata json includes secret_id key."
    },
    "vaultbridgesdk_e_20103" : {
        "code" : "vaultbridgesdk_e_20103",
        "http_status_code" : 404,
        "message" : "The Cloud Pak secret type is mismatched with vault secret type, ensure secret type on CloudPak aligns / matches with secret type on the vault.",
        "reason" : "Secret type on the Cloud Pak does not align / match with the secret type on the vault.",
        "action" : "Ensure secret type on the Cloud Pak aligns / matches with secret type on the vault."
    },
    "vaultbridgesdk_e_20200" : {
        "code" : "vaultbridgesdk_e_20200",
        "http_status_code" : 404,
        "message" : "Bulk secret - The secret reference data is missing, ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata.",
        "reason" : "The query parameter secret_reference_metadata is not specified.",
        "action" : "Ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata."
    },
    "vaultbridgesdk_e_20201" : {
        "code" : "vaultbridgesdk_e_20201",
        "http_status_code" : 404,
        "message" : "Bulk secret - secret reference data is malformed and not a valid json, ensure secret metadata is a valid json.",
        "reason" : "Secret metadata is not a valid json",
        "action" : "Ensure secret metadata is a valid json array with keys secret_type, secret_id, and secret_urn."
    },
    "vaultbridgesdk_e_20500" : {
        "code" : "vaultbridgesdk_e_20500",
        "http_status_code" : 500,
        "message" : "Received exception from the vault, check vault bridge log for further details.",
        "reason" : "Received exception from the vault when processing the request.",
        "user_action" : "Check the vault bridge logs for the further error details."
    },
    "vaultbridgesdk_e_20900" : {
        "code" : "vaultbridgesdk_e_20900",
        "http_status_code" : 500,
        "message" : "Encountered internal exception while processing the request, check the vault bridge logs for the further details.",
        "reason" : "Encountered internal exception while processing the request.",
        "user_action" : "Check the vault bridge logs for the further error details."
    }
}