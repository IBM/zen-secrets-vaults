import os, sys

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from vault_sdk.bridges.ibm_secrets_manager.ibm_secrets_manager_bridge import IBMSecretManager
from vault_sdk.bridges.azure_key_vault.azure_key_vault_bridge import AzureKeyVault
from bridges_common.constants import *

CLASS_LOOKUP = { IBM_SECRETS_MANAGER : IBMSecretManager, AWS: None, AZURE_KEY_VAULT: AzureKeyVault }
