# IBM Cloud Pak Vault Bridge installation

## [1] Overview

There are 2 vault bridge deployment options.

### [1.1] Kubernetes (K8s) deployment (Running in the same Cloud Pak cluster)

With this option, the vault bridge runs on the same Cloud Pak cluster and leverages the Kubernetes high availability and load balancer functionality.

![image](/docs/images/InstallOptionK8sDeploy.jpg)

### [1.2] Standalone bridge (Running outside Cloud Pak cluster)

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
1. Download and clone this repository
2. Generate and configure TLS key and certificate
3. Install JWT public key
4. Run bridge server



