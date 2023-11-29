# IBM Cloud Pak Vault Bridge installation

## [1] Overview

### [1.1] Prerequisite

Cloud Pak for Data Version 4.8 is required to use the Vault SDK bridge.

### [1.2] Vault bridge deployment options

There are 2 vault bridge deployment options.

#### [1.2.1] Kubernetes (K8s) deployment (Running in the same Cloud Pak cluster)

With this option, the vault bridge runs on the same Cloud Pak cluster and leverages the Kubernetes high availability and load balancer functionality.

![image](/docs/images/InstallOptionK8sDeploy.jpg)

#### [1.2.2] Standalone bridge (Running outside Cloud Pak cluster)

With this option, the vault bridge runs on separate servers. For high availability, you must configure multiple servers and a load balancer.

This option is used for providing isolation from Cloud Pak components. The vault bridge runs on the servers that are managed by the security group.

![image](/docs/images/InstallOptionStandalone.jpg)

## [2] Installation steps

### [2.1] Kubernetes (K8s) deployment
1. Download the scripts from [kubernetes scripts](/scripts/install_kubernetes) 
2. Execute the following scripts. Pause after each step and verify successful completion.
3. Use the bridge URL `https://ibm-zen-vault-bridge-svc` when you configure vaults in Cloud Pak for Data.

#### [2.1.1] Set project
```
export ZEN_NAMESPACE=zen
```    

#### [2.1.2] Allow TLS to use private certificate authority (CA)

Set flag in Zenservice CR (custom resource) to tolerate private certificate authority (CA)

```
oc --namespace $ZEN_NAMESPACE \
patch zenservice lite-cr \
--type=merge \
--patch '{"spec": {"vault_bridge_tls_tolerate_private_ca": true}}'
```

Wait for the operator to reconcile. Check the status after 15 minutes.

```
oc --namespace $ZEN_NAMESPACE get zenservice lite-cr -o jsonpath='{.status.Progress}{"-"}{.status.zenStatus}{"\n"}'
```
Expected response
```
100%-Completed
```

#### [2.1.3] Create vault bridge TLS certificate
```
oc -n $ZEN_NAMESPACE create -f 01_vault_bridge_tls_certificates.yaml
```
Check certificate status
```
oc -n $ZEN_NAMESPACE wait certificate.cert-manager.io/ibm-zen-vault-bridge-server --for=condition=Ready --timeout=30s
```
#### [2.1.4] Create vault bridge Kubernetes deployment
```
oc -n $ZEN_NAMESPACE create -f 02_vault_bridge_deployment.yaml
```
Check status
```
oc -n $ZEN_NAMESPACE  wait pods -l component=ibm-zen-vault-bridge --for=condition=Ready --timeout=30s
```
#### [2.1.5] Create vault bridge Kubernetes service
```
oc -n $ZEN_NAMESPACE create -f 03_vault_bridge_service.yaml
```
Check status
```
oc -n $ZEN_NAMESPACE  get service -l component=ibm-zen-vault-bridge
```
#### [2.1.6] Vault bridge health check validation
```
oc -n zen exec -t $(oc get po -l component=ibm-nginx --no-headers -o custom-columns=:metadata.name | awk 'FNR <=1') -c ibm-nginx-container -- bash -c "curl -ks https://ibm-zen-vault-bridge-svc/v2/health"
```
Expected response
```
{"status": "OK"}
```


### [2.2] Standalone bridge
#### [2.2.1] Allow TLS to use private certificate authority (CA)
See here - [[2.1.2] Allow TLS to use private certificate authority (CA)](#212-allow-tls-to-use-private-certificate-authority-ca)

#### [2.2.2] Download or clone the repository
Download or clone this repository on the server where you want to run the bridge. Then, go to the root of this repository.
```
git clone https://github.com/IBM/zen-secrets-vaults.git
```

#### [2.2.3] Install dependencies
1. Check your Python version. <br>The recommended version is Python 3.11.</br>
    ```
    python3 --version
    pip3 --version
    ```
2. Install the Python dependencies that are listed in [requirements.txt](/requirements.txt)
    ```
    python3 -m pip install -r requirements.txt
    ```

#### [2.2.4] Export JWT public key from the CPD cluster
To verify JSON Web Token, the public key from the `ibm-zen-vault-sdk-jwt` secret on the Cloud Pak for Data cluster needs to be copied to bridge server.
```
export ZEN_NAMESPACE=zen
oc -n $ZEN_NAMESPACE extract secrets/ibm-zen-vault-sdk-jwt --to=. --keys=public.pem
```
Copy `public.pem` to the bridge server and put it in the JWT public key folder.

#### [2.2.5] Configure TLS key and certificate
To make sure that the server connection is secure, you need a TLS certificate and key pair for the encryption of server connections. You also need a public key to validate the JWT token.

If the TLS key and certificate are available, update the environment variables `TLS_CERTIFICATE_FILE_PATH`, `TLS_KEY_FILE_PATH`, and `JWT_PUBLIC_KEY_PATH` to the actual path of `cert.pem`, `key.pem`, and `public.pem`.
```
export TLS_CERTS_LOCATION="/path/to/tls-certs-folder"
export JWT_PUBLIC_KEY_LOCATION="/path/to/jwt-pub-key-folder"
mkdir -p ${TLS_CERTS_LOCATION} && mkdir -p ${JWT_PUBLIC_KEY_LOCATION}

export TLS_CERTIFICATE_FILE_PATH="${TLS_CERTS_LOCATION}/cert.pem"
export TLS_KEY_FILE_PATH="${TLS_CERTS_LOCATION}/key.pem"
export JWT_PUBLIC_KEY_PATH="${JWT_PUBLIC_KEY_LOCATION}/public.pem"
```
Otherwise, you can run the following commands to generate a self-signed TLS certificate and key pair.
```
openssl req -x509 -newkey rsa:4096 -keyout ${TLS_KEY_FILE_PATH} -out ${TLS_CERTIFICATE_FILE_PATH} -sha256 -days 3650 -nodes -subj "/C={Country}/ST={State}/L={City}/O={OrgName}/OU={OrgUnitName}/CN={bridge-server-name}"
```

#### [2.2.6] Run bridge server
To start the bridge server, complete the following steps:
1. Start the bridge server and run it in the background.
    ```
    nohup scripts/start_server.sh > server.log 2>&1 &
    ```
2. Validate the health of the vault bridge.
    ```
    curl -kv "https://<bridge-server-name>:8443/v2/health"
    ```
    Expected response
    ```
    {"status": "OK"}
    ```


