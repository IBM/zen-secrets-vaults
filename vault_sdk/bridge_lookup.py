from bridges.ibm_secrets_manager.ibm_secrets_manager_bridge import IBMSecretManager
from bridges.azure_key_vault.azure_key_vault_bridge import AzureKeyVault
from constants import *

CLASS_LOOKUP = { IBM_SECRETS_MANAGER : IBMSecretManager, AWS: None, AZURE_KEY_VAULT: AzureKeyVault }
