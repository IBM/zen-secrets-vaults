# Developing a vault bridge using SDK

## [1] Overview

1. Download and clone this repository.
2. Gather the following vault information.

    a. Capture the following: 
    - Vault connection information
    - Vault access information

    b. Identify secret types supported by the vault.

    c. Identify REST API to get secret details from the vault.
3. Define the following extensions:
    - Vault - This includes vault connection and access information
    - Secret - This includes supported secret types and secret identifier
4. Develop a bridge using vault bridge SDK by implementing the API with [this specification](/swagger/api.yaml).
