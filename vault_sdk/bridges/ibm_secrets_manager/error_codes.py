# COMPONENT_NAME and COMPONENT_TYPE are used by doc generator to insert as section header in docs/apidoc/error_codes.md
COMPONENT_NAME = "IBM Cloud Secrets Manager"
COMPONENT_TYPE = "Vault Bridge"

COMPONENT_EXCEPTIONS = {
    "vaultbridgesdk_e_22001" : {
        "code" : "vaultbridgesdk_e_22001",
        "http_status_code" : 404,
        "message" : "Received insufficient vault authentication information. Ensure all required attributes are passed in the vault-auth HTTP header.",
        "reason" : "Expected 2 attributes included in the vault authentication however received less than 2.",
        "action" : "Ensure all required attributes `VAULT_URL` and `API_KEY` are passed in the vault-auth HTTP header."
    },
    "vaultbridgesdk_e_22002" : {
        "code" : "vaultbridgesdk_e_22002",
        "http_status_code" : 404,
        "message" : "Received incomplete vault authentication information. Ensure attributes are passed in the vault-auth HTTP header does not have empty value.",
        "reason" : "Value of the attributes passed in the vault-auth HTTP header has empty values.",
        "action" : "Ensure vault-auth HTTP header attributes `VAULT_URL` and `API_KEY` do not have empty values."
    },
    "vaultbridgesdk_e_22101" : {
        "code" : "vaultbridgesdk_e_22101",
        "http_status_code" : 404,
        "message" : "Malformed secret metadata passed in the query parameter secret_reference_metadata. Ensure secret metadata is valid JSON.",
        "reason" : "Secret metadata passed in the query parameter secret_reference_metadata is not valid JSON.",
        "action" : "Ensure secret metadata passed in the query parameter secret_reference_metadata is valid JSON with key secret_id."
    },
    "vaultbridgesdk_e_22102" : {
        "code" : "vaultbridgesdk_e_22102",
        "http_status_code" : 404,
        "message" : "Missing `secret_id`. Ensure secret metadata JSON includes key `secret_id`.",
        "reason" : "The `secret_id` is missing from the secret metadata JSON.",
        "action" : "Ensure secret metadata JSON includes `secret_id` key."
    },
    "vaultbridgesdk_e_22103" : {
        "code" : "vaultbridgesdk_e_22103",
        "http_status_code" : 404,
        "message" : "The Cloud Pak for Data (or other) secret type is mismatched with vault secret type. Ensure secret type on CloudPak aligns or matches with secret type on the vault.",
        "reason" : "Secret type on the Cloud Pak for Data (or other) does not align or match with the secret type on the vault.",
        "action" : "Ensure secret type on the Cloud Pak for Data (or other) is aligned or matched with secret type on the vault."
    },
    "vaultbridgesdk_e_22200" : {
        "code" : "vaultbridgesdk_e_22200",
        "http_status_code" : 404,
        "message" : "Bulk secret - The secret reference data is missing. Ensure Base64 encoded secret metadata is included in the secret_reference_metadata query parameter.",
        "reason" : "The query parameter secret_reference_metadata is not specified.",
        "action" : "Ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata."
    },
    "vaultbridgesdk_e_22201" : {
        "code" : "vaultbridgesdk_e_22201",
        "http_status_code" : 404,
        "message" : "Bulk secret - secret reference data is malformed and not a valid JSON array. Ensure secret metadata is valid JSON.",
        "reason" : "Secret metadata is not a valid JSON",
        "action" : "Ensure secret metadata is a valid JSON array with keys `secret_type`, `secret_id`, and `secret_urn`."
    },
    "vaultbridgesdk_e_22500" : {
        "code" : "vaultbridgesdk_e_22500",
        "http_status_code" : 500,
        "message" : "Received exception from the vault. Check vault bridge log for more details.",
        "reason" : "Received exception from the vault when processing the request.",
        "action" : "Check the vault bridge logs for more details."
    },
    "vaultbridgesdk_e_22501" : {
        "code" : "vaultbridgesdk_e_22501",
        "http_status_code" : 500,
        "message" : "Encountered internal exception while requesting authentication token from the IAM, check the vault bridge logs for the further details.",
        "reason" : "Encountered internal exception while requesting vault token",
        "action" : "Check the vault bridge logs for more details."
    },
    "vaultbridgesdk_e_22900" : {
        "code" : "vaultbridgesdk_e_22900",
        "http_status_code" : 500,
        "message" : "Encountered internal exception while processing the request. Check the vault bridge logs for more details.",
        "reason" : "Encountered internal exception while processing the request.",
        "action" : "Check the vault bridge logs for more details."
    }
}