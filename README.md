# zen-secrets-vaults

## [1] Overview of secrets and vaults
A secret contains sensitive data. You can use secrets to store a variety of information, such as:
- Usernames and passwords
- SSL certificates
- API keys
- Authentication tokens

A vault is a secure place to store and manage secrets. 

Secrets offer several advantages over traditional plain-text entry:
- The information in the secret is stored in a secure and encrypted environment that conforms to your organization's policies.
- The services and connections that use the secret do not have direct access to the information in the secret.
- The information in the secret can be updated once. The change is automatically picked up by all services or connections that use the secret.

## [2] Vault bridge SDK

Services running on Cloud Pak for Data can use a vault bridge through `Platform Core API` to integrate with an enterprise vault.
The following vault bridges are included in Cloud Pak for Data.
1. CyberArk AAM
2. HashiCorp

---

**NOTE** -  Cloud Pak for Data and the vault bridge SDK do not include any vaults. The vault bridge only integrates with vaults by using public APIs provided by the vault vendors. Vaults are managed by the customer. 

---


Users can use the vault bridge SDK to integrate Cloud Pak for Data with additional vaults by applying the `Build Your Own Vault Bridge` concept. The SDK improves the agility and speed to market ability of your organization by complying with security or regulatory requirements.

A bridge that is developed by using the vault bridge SDK dynamically plugs in to the platform with extension and dynamically renders the user interface by using extension configuration.

As a quick start, the bridge samples for the following vaults are provided.
1. AWS Secrets Manager
2. Azure Key Vault
3. IBM Cloud Secrets Manager

### [2.1] Vault bridge interaction

The following diagram illustrates how Cloud Pak for Data users can fetch the credentials from the vault to access data in the data source. This example shows 2 paths for vault integration.
1. Using embedded vault bridge
2. Using SDK based vault bridge

![image](/docs/images/FetchSecretInteraction.jpg)


1. Cloud Pak for Data user logs in to the console, and through a Cloud Pak for Data service user, requests data processing on data in the data source.
2. Cloud Pak for Data service requests a secret identifier from the `Platform Connection`.
3. Cloud Pak for Data service receives a secret identifier.
4. Using the secret identifier, Cloud Pak for Data service requests secret details from the `Platform Core API`.
5. `Platform Core API` validates user access and determines vault bridge type using secret identifier and routes request to one of the follow vault bridges:
    - Embedded vault bridge
        - 5a. Bridge requests secret details directly from the vault.
    - SDK based vault bridge
        - 5y. `Platform Core API` forwards request to SDK based bridge.
        - 5z. SDK based bridge requests secret details from the vault.
6. Cloud Pak for Data service receives secret details.
7. Using secret details and the connection information, Cloud Pak for Data service requests data from the data source.
8. Cloud Pak for Data service receives the data and performs the requested operation on the retrieved data.

### [2.2] Vault bridge SDK components

The following diagram shows vault bridge SDK components. Some of the components reside on the platform. The SDK is implemented in Python 3 and can be installed on or outside the platform cluster. 

![image](/docs/images/VaultBridgeSDKComponents.jpg)

#### [2.2.1] Platform components

1. Platform user interface

    Users with an appropriate vault role can manage vaults and secrets in the Cloud Pak for Data web client. The `vault bridge SDK UI framework` dynamically generates a user interface for a vault bridge by using the information in the vault bridge extension.

2. Platform Core API

    The Platform Core API receives a GET /v2/secrets/{secret-urn} request from Cloud Pak for Data consumers (such as services, the web client user interface, and so on). Using a secret urn (also known as secret identifier) it routes that request to the appropriate vault bridge. In the case of the bridge created using `vault bridge SDK` it delegates a request to the bridge server.

3. Extensions

    The vault and secret extensions dynamically plugs in the vault bridge into the `Cloud Pak for Data Platform`. These extensions define characteristics of the bridge using the following information. The UI framework dynamically generates a user interface by using the information in the extension.  
    1. Vault extension
        - Vault credentials information 
        - Vault connection information
        - Supported secret types
    2. Secret extension
        - Secret identifier

4. JWT private key

    The vault bridge SDK is secured using JSON Web Token(JWT). The `Platform Core API` generates JWT using a private key and attaches JWT to every request sent to the vault bridge server.


#### [2.2.1] SDK components

1. Vault bridge API server

    The API server is implemented in Python 3 and responsible for,
    1. Authentication.
    2. Request validation.
    3. Routing request to the specific bridge. 
2. JWT public key

    The vault bridge SDK is secured using JSON Web Token(JWT). Using the public key, the bridge API server validates JWT to authenticate the consumer.
3. Vault bridge(s)

    The bridge is implemented in Python 3 and responsible for:
    1. Connecting to the vault using vault authentication information.
    2. Requesting secret detail from the vault using secret reference data.




## [3] Resources

1. [Bridge installation](/docs/01_installation/bridge_installation.md)
2. [Configuring vault integration](/docs/02_configuration/configure_vault_integration.md)
3. [Cloud Pak for Data API documentation](https://cloud.ibm.com/apidocs/cloud-pak-data/cloud-pak-data-4.8.0#managing-secrets-and-vaults)

