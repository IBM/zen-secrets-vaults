# Azure Key Vault

To store secrets on Azure Key Vault, follow these instructions.

## [1] Azure Setup

### [1.1] App Registration, Resource Group
1. Open the [Azure portal](https://portal.azure.com/).
2. Sign up or sign in to an Azure account.

### [1.2] New Azure Key Vault

1. Sign in to the [Azure portal](https://portal.azure.com/).
2. Click on **Create a resource** and search for **Key Vault**.
3. Click **Key Vault** then click the **Create**.
4. Fill in the required details such as the subscription, resource group, vault name, region, and pricing tier. 

## [2] Secret types and mapping

Cloud Pak Secret Type | Azure Key Vault Secret Type | How to store a secret
---|---|---
Username and password | Choose Manual <br><br> | Store a JSON with the following keys<br>1. username<br>2. password
Key | Choose Manual<br> | Store a JSON with the following keys<br>1. key
Token | Choose Manual<br> | Store a JSON with the following keys<br>1. token
TLS certificate	| Multi-line secret setup through PowerShell<br><br> | Using PowerShell store a secret as multi-line secret with the following attributes<br>1. cert<br>2. key(optional)
Custom | Choose Manual | Store a JSON with the user-defined keys

### [2.1] Creating multi-line secret using Azure Powershell 

For more information, see [Store a multi-line secret in Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/secrets/multiline-secrets).

1. Run the following command to install PowerShell on your machine.

    `Mac OS`
    ```bash
    brew install powershell --cask
    ```
2. Run pwsh on your terminal.

    `Mac OS`
    ```bash $ pwsh
    PowerShell 7.3.6
    PS /Users/admin>
    ```
3. Install Azure Powershell.

    ```PowerShell
    PS /Users/admin> Install-Module -Name Az -AllowClobber -Force
    PS /Users/admin>
    ```

4. Run the following command to log in to your Azure account:

    ```PowerShell
    PS /Users/admin> Connect-AzAccount
    ```

    **Output**
    ```PowerShell
    Account                     SubscriptionName        TenantId

    -------                     ----------------        --------                     
    john.doe@example-co.com     Azure for Example-Co    ee8b30f8-wiuj-49ad-988b-1245…
    PS /Users/admin> 
    ```

5. Set the **vaultName** that was created in the UI and the **secretName** that you want for a multi-line secret.

    ```PowerShell
    PS /Users/admin> $vaultName = "example-coazurevault"    
    PS /Users/admin> $secretName = "cpd-access-cert"
    ```

6. Create a secret.

    6.1 Set secret value to a variable.

    ```PowerShell
    PS /Users/admin> $secretValue = @"
    cert=-----BEGIN CERTIFICATE-----
    MIIEvzCCA6egAwIBAgIIIE8SzorQ21cwDQYJKoZIhvcNAQELBQAwaDELMAkGA1UE
    .
    .
    .
    HHXi+UiDoiAC+EjS72jyX6uozw==
    -----END CERTIFICATE-----
    key=-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA32fUWlSkkiltH34qCHC9ltIuTTSqUYUMy1XVlrf4JB2MaiPM
    .
    .
    .
    JPU+0Qt85Ix5KqZ8DcmUJpF6cdmgfkmX8TVU+wxduMk/u+4tMLu3
    -----END RSA PRIVATE KEY---
    "@
    ```

    6.2  Covert value to secrue string.

    ```PowerShell
    PS /Users/admin> $secureSecretValue = ConvertTo-SecureString $secretValue -AsPlainText -Force                
    ```

    6.3 Set secret on the vault.

    ```PowerShell
    PS /Users/admin> Set-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -SecretValue $secureSecretValue
    ```
