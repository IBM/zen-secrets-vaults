# Cloud Pak vault and secret configuration

## [1] Prerequisites

Secrets must be created on the vault before you configure vault integration on the Cloud Pak.
For the requirements on how to configure secret on the vault, see [Vault secret configuration](/docs/02_configuration/vaults).  

## [2] Install extensions on the Cloud Pak cluster

Extension for the following vaults are provided. For more information, see [Vault and secret extensions](/extensions).
1. AWS Secrets Manager
2. Azure Key Vault
3. IBM Secrets Manager

### [2.1] Get Platform token

```
curl -k -X POST https://${CPD_ROUTE}/icp4d-api/v1/authorize \ 
-H "content-type: application/json" \ 
-d '{"username": "<username>","password": "<password>"}'
```

### [2.2] Install vault extension


```
curl -k -X POST https://${CPD_ROUTE}/zen-data/v1/extensions \ 
-H "content-type: application/json" \ 
-H "Authorization: Bearer <platform-token>" \ 
--data-binary "@vault-extension.json"
```

### [2.3] Install secret extension

```
curl -k -X POST https://${CPD_ROUTE}/zen-data/v1/extensions \ 
-H "content-type: application/json" \ 
-H "Authorization: Bearer <platform-token>" \ 
--data-binary "@secret-extension.json" 
```


## [3] Configure vault integrations and secrets on the Cloud Pak

You can connect to external vaults that store secrets to enable users and applications to retrieve the content of the secrets from the vaults as needed.

Permissions you need for this task
    To add integration to a vault, you must have the following permissions:
    - Add vaults permission.

When you need to complete this task
Complete this task if you need to use a secret from an external vault in Cloud Pak for Data.

### [3.1] Procedure

To connect to an external vault through vault bridge:

1. From the navigation menu, select **Administration** > **Configurations**.
2. Open the Vaults and secrets card.
3. On the **Vaults** tab, click **Add vault**.
4. Enter a name and a description for the vault.
    The name can contain only alphanumeric characters and hyphens.
5. Select the type of vault that you want to integrate with.

    AWS Secrets Manager
    Field | Details
    ------|--------
    Bridge URL | The fully qualified URL of the bridge. The URL must have the following format: http://bridge-location.example.com:port. If the bridge is running as a Kubernetes deployment on the same cluster, use https://ibm-zen-vault-bridge-svc.
    Vault URL | The fully qualified URL of the vault that you want to connect to. The URL must have the following format: http://vault-location.example.com:port.
    Access Key ID | Key ID used for API authorization, it is part key ID and secret set and long-term security credential.
    Secret Access Key | Secret used for API authorization, it is part key ID and secret set and long-term security credential.

    Azure Key Vault
    Field | Details
    ------|--------
    Bridge URL | The fully qualified URL of the bridge. The URL must have the following format: http://bridge-location.example.com:port. If the bridge is running as a Kubernetes deployment on the same cluster, use https://ibm-zen-vault-bridge-svc.
    Vault URL | The fully qualified URL of the vault that you want to connect to. The URL must have the following format: http://vault-location.example.com:port.
    Tenant ID | The directory tenant the application plans to operate against, in GUID or domain-name format.
    Client ID | The application ID that's assigned to your app. You can find this information in the portal where you registered your app.
    Client Secret | The client secret that you generated for your app in the app registration portal. 

    IBM Secrets Manager
    Field | Details
    ------|--------
    Bridge URL | The fully qualified URL of the bridge. The URL must have the following format: http://bridge-location.example.com:port. If the bridge is running as a Kubernetes deployment on the same cluster, use https://ibm-zen-vault-bridge-svc.
    Vault URL | The fully qualified URL of the vault that you want to connect to. The URL must have the following format: http://vault-location.example.com:port.
    API Key | Key for API authorization, this is created from IBM Cloud console.


6. Click **Next**.

Add a reference to a secret that exists in the external vault. You must add the reference to one secret when you first create the new vault integration so that you can test the integration. You can add references to more secrets later.

7. Enter a name and an optional description for the secret.
    The name can contain only alphanumeric characters and hyphens.
8. Select the type of information that is stored in the secret:

    AWS Secrets Manager
    Secret type | Details
    ------|--------
    Username and password | The secret is used to store a username and password for authentication.
    Key | The secret is used to store a key for authentication.
    Token | The secret is used to store a token for authentication.
    TLS certificate	| The secret is used to store an TLS certificate for authentication.
    Custom | The secret is used to store custom information. The custom secret does include fields that are required by other secret types.

    Azure Key Vault
    Secret type | Details
    ------|--------
    Username and password | The secret is used to store a username and password for authentication.
    Key | The secret is used to store a key for authentication.
    Token | The secret is used to store a token for authentication.
    TLS certificate	| The secret is used to store an TLS certificate for authentication.
    Custom | The secret is used to store custom information. The custom secret does include fields that are required by other secret types.

    IBM Secrets Manager
    Secret type | Details
    ------|--------
    Username and password | The secret is used to store a username and password for authentication.
    Key | The secret is used to store a key for authentication.
    TLS certificate |	The secret is used to store an TLS certificate for authentication.
    Custom | The secret is used to store custom information. The custom secret does include fields that are required by other secret types.


9. Enter the secret details, as follows:

    AWS Secrets Manager
    Field | Details
    ------|--------
    Secret name| The name of the secret in the vault.

    Azure Key Vault
    Field | Details
    ------|--------
    Secret name| The name of the secret in the vault.

    IBM Secrets Manager
    Field | Details
    ------|--------
    Secret ID| The ID of the secret in the vault.

10. Select the users and groups that you want to share the secret with.
    Those users can access only the secret that you share. They do not have access to the vault or any other secrets in the vault.
    You cannot share secrets that are shared with you.

11. Click **Create**.

### Results
The connection to the vault is created.
You can update the vault configuration as necessary. (If you update the configuration, test the integration again.)