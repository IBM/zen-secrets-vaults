FRAMEWORK_EXCEPTIONS = {
    "vaultbridgesdk_e_10001" : {
        "code" : "vaultbridgesdk_e_10001",
        "http_status_code" : "401",
        "message" : "Unable to authenticate using provided JWT, ensure valid JWT is included in the request.",
        "reason" : "Invalid JWT is passed in Authorization header.",
        "user_action" : "Ensure valid JWT is passed as Bearer token in Authorization header."
    },
    "vaultsdkbridge_e_10002" : {
        "code" : "vaultsdkbridge_e_10002",
        "http_status_code" : "400",
        "message" : "Vault type specified in the URI path is not supported, include valid vault type in the URI path.",
        "reason" : "Vault type specified in the URI path is not supported",
        "user_action" : "Include supported vault type in URI path"
    },
    "vaultbridgesdk_e_10003" : {
        "code" : "vaultbridgesdk_e_10003",
        "http_status_code" : "400",
        "message" : "Secret type specified in the query parameter `secret_type` is not supported, specify valid secret type is included in the query parameter secret_type.",
        "reason" : "Secret type specified in the query parameter `secret_type` is not supported.",
        "user_action" : "Specify valid secret type is included in the query parameter secret_type."
    },
    "vaultbridgesdk_e_10501" : {
        "code" : "vaultbridgesdk_e_10501",
        "http_status_code" : "400",
        "message" : "Vault authentication header is missing, specify vault connection information in the vault authentication header ",
        "reason" : "Vault-Auth is missing from the HTTP header",
        "user_action" : "Specify vault connection information in Vault-Auth header"
    },
    "vaultbridgesdk_e_10502" : {
        "code" : "vaultbridgesdk_e_10502",
        "http_status_code" : "400",
        "message" : "Query parameter secret_type is missing from the request, specify valid secret type in query parameter secret_type",
        "reason" : "Query parameter secret_type is missing from the request",
        "user_action" : "Specify valid secret type is included in the query parameter secret_type."
    },
    "vaultbridgesdk_e_10503" : {
        "code" : "vaultbridgesdk_e_10503",
        "http_status_code" : "400",
        "message" : "Query parameter secret_reference_metadata is invalid or missing, specify valid secret metadata in query parameter secret_reference_metadata",
        "reason" : "Query parameter secret_reference_metadata is missing or empty from the request",
        "user_action" : "Specify secret metadata in the query parameter secret_reference_metadata"
    },
    "vaultbridgesdk_e_10900" : {
        "code" : "vaultbridgesdk_e_10900",
        "http_status_code" : "500",
        "message" : "Encountered internal exception while processing request, check vault brige log for further details.",
        "reason" : "Encountered internal exception while processing request",
        "user_action" : "Check the vault bridge logs for the further error details."
    }  

}