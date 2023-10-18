# Error codes 
This document lists various error codes returned by vault bridge SDK and provides information on the corrective action. 
### Vault Bridge SDK Framework  - Error codes
#### vaultbridgesdk_e_10001:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_10001
|**Reason** | Invalid JWT is passed in Authorization header.
|**Action** | Ensure valid JWT is passed as Bearer token in Authorization header.
#### vaultsdkbridge_e_10002:

|  | **Description** 
|--|--
|**Code** | vaultsdkbridge_e_10002
|**Reason** | Vault type specified in the URI path is not supported
|**Action** | Include supported vault type in URI path
#### vaultbridgesdk_e_10003:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_10003
|**Reason** | Secret type specified in the query parameter `secret_type` is not supported.
|**Action** | Specify valid secret type is included in the query parameter secret_type.
#### vaultbridgesdk_e_10501:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_10501
|**Reason** | Vault-Auth is missing from the HTTP header
|**Action** | Specify vault connection information in Vault-Auth header
#### vaultbridgesdk_e_10502:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_10502
|**Reason** | Query parameter secret_type is missing from the request
|**Action** | Specify valid secret type is included in the query parameter secret_type.
#### vaultbridgesdk_e_10503:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_10503
|**Reason** | Query parameter secret_reference_metadata is missing or empty from the request
|**Action** | Specify secret metadata in the query parameter secret_reference_metadata
#### vaultbridgesdk_e_10900:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_10900
|**Reason** | Encountered internal exception while processing request
|**Action** | Check the vault bridge logs for the further error details.


### Vault Bridge AWS Secrets Manager - Error codes
#### vaultbridgesdk_e_20001:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20001
|**Reason** | Expected 3 attributes included in the vault-auth HTTP header however received less than 3.
|**Action** | Ensure all required attributes `VAULT_URL`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` are passed in the vault-auth HTTP header.
#### vaultbridgesdk_e_20002:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20002
|**Reason** | Value of the attributes passed in the vault-auth HTTP header have empty values.
|**Action** | Ensure vault-auth HTTP header attributes `VAULT_URL`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` do not have empty values.
#### vaultbridgesdk_e_20101:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20101
|**Reason** | Secret metadata passed in the query parameter secret_reference_metadata is not valid JSON.
|**Action** | Ensure secret metadata passed in the query parameter secret_reference_metadata is valid JSON with key secret_id.
#### vaultbridgesdk_e_20102:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20102
|**Reason** | The secret_id is missing from the secret metadata JSON.
|**Action** | Ensure secret metadata JSON includes secret_id key.
#### vaultbridgesdk_e_20103:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20103
|**Reason** | Secret type on the Cloud Pak for Data (or other) does not align or match with the secret type on the vault.
|**Action** | Ensure secret type on the Cloud Pak for Data (or other) is aligned or matched with secret type on the vault.
#### vaultbridgesdk_e_20200:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20200
|**Reason** | The query parameter secret_reference_metadata is not specified.
|**Action** | Ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata.
#### vaultbridgesdk_e_20201:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20201
|**Reason** | Secret metadata is not a valid JSON
|**Action** | Ensure secret metadata is a valid JSON array with keys `secret_type`, `secret_id`, and `secret_urn`.
#### vaultbridgesdk_e_20500:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20500
|**Reason** | Received exception from the vault when processing the request.
|**Action** | Check the vault bridge logs for more details.
#### vaultbridgesdk_e_20900:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_20900
|**Reason** | Encountered internal exception while processing the request.
|**Action** | Check the vault bridge logs for more details.


### Vault Bridge Azure Key Vault - Error codes
#### vaultbridgesdk_e_21001:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21001
|**Reason** | Expected 4 attributes included in the vault authentication however received less than 4.
|**Action** | Ensure all required attributes `VAULT_URL`, `TENANT_ID`, `CLIENT_ID`, and `CLIENT_SECRET` are passed in the vault-auth HTTP header.
#### vaultbridgesdk_e_21002:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21002
|**Reason** | Value of the attributes passed in the vault-auth HTTP header has empty values.
|**Action** | Ensure vault-auth HTTP header attributes `VAULT_URL`, `TENANT_ID`, `CLIENT_ID`, and `CLIENT_SECRET` do not have empty values.
#### vaultbridgesdk_e_21101:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21101
|**Reason** | Secret metadata passed in the query parameter secret_reference_metadata is not valid JSON.
|**Action** | Ensure secret metadata passed in the query parameter secret_reference_metadata is valid JSON with key secret_name.
#### vaultbridgesdk_e_21102:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21102
|**Reason** | The `secret_name` is missing from the secret metadata JSON.
|**Action** | Ensure secret metadata JSON includes `secret_name` key.
#### vaultbridgesdk_e_21103:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21103
|**Reason** | Secret type on the Cloud Pak for Data (or other) does not align or match with the secret type on the vault.
|**Action** | Ensure secret type on the Cloud Pak for Data (or other) is aligned or matched with secret type on the vault.
#### vaultbridgesdk_e_21200:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21200
|**Reason** | The query parameter secret_reference_metadata is not specified.
|**Action** | Ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata.
#### vaultbridgesdk_e_21201:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21201
|**Reason** | Secret metadata is not a valid JSON
|**Action** | Ensure secret metadata is a valid JSON array with keys `secret_type`, `secret_name`, and `secret_urn`.
#### vaultbridgesdk_e_21500:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21500
|**Reason** | Received exception from the vault when processing the request.
|**Action** | Check the vault bridge logs for more details.
#### vaultbridgesdk_e_21501:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21501
|**Reason** | Encountered internal exception while requesting vault token
|**Action** | Check the vault bridge logs for more details.
#### vaultbridgesdk_e_21900:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_21900
|**Reason** | Encountered internal exception while processing the request.
|**Action** | Check the vault bridge logs for more details.


### Vault Bridge IBM Cloud Secrets Manager - Error codes
#### vaultbridgesdk_e_22001:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22001
|**Reason** | Expected 2 attributes included in the vault authentication however received less than 2.
|**Action** | Ensure all required attributes `VAULT_URL` and `API_KEY` are passed in the vault-auth HTTP header.
#### vaultbridgesdk_e_22002:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22002
|**Reason** | Value of the attributes passed in the vault-auth HTTP header has empty values.
|**Action** | Ensure vault-auth HTTP header attributes `VAULT_URL` and `API_KEY` do not have empty values.
#### vaultbridgesdk_e_22101:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22101
|**Reason** | Secret metadata passed in the query parameter secret_reference_metadata is not valid JSON.
|**Action** | Ensure secret metadata passed in the query parameter secret_reference_metadata is valid JSON with key secret_id.
#### vaultbridgesdk_e_22102:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22102
|**Reason** | The `secret_id` is missing from the secret metadata JSON.
|**Action** | Ensure secret metadata JSON includes `secret_id` key.
#### vaultbridgesdk_e_22103:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22103
|**Reason** | Secret type on the Cloud Pak for Data (or other) does not align or match with the secret type on the vault.
|**Action** | Ensure secret type on the Cloud Pak for Data (or other) is aligned or matched with secret type on the vault.
#### vaultbridgesdk_e_22200:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22200
|**Reason** | The query parameter secret_reference_metadata is not specified.
|**Action** | Ensure base64 encoded secret metadata is included in the query parameter secret_reference_metadata.
#### vaultbridgesdk_e_22201:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22201
|**Reason** | Secret metadata is not a valid JSON
|**Action** | Ensure secret metadata is a valid JSON array with keys `secret_type`, `secret_id`, and `secret_urn`.
#### vaultbridgesdk_e_22500:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22500
|**Reason** | Received exception from the vault when processing the request.
|**Action** | Check the vault bridge logs for more details.
#### vaultbridgesdk_e_22501:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22501
|**Reason** | Encountered internal exception while requesting vault token
|**Action** | Check the vault bridge logs for more details.
#### vaultbridgesdk_e_22900:

|  | **Description** 
|--|--
|**Code** | vaultbridgesdk_e_22900
|**Reason** | Encountered internal exception while processing the request.
|**Action** | Check the vault bridge logs for more details.


