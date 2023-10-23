# IBM Cloud Secrets Manager

To store secrets on IBM Cloud Secrets Manager, follow these instructions.

## [1] IBM Cloud Setup

### [1.1] API Key setup

1. Login to [IBM Cloud](https://cloud.ibm.com). 
2. On the **Manage** menu, select **Access (IAM)** OR go to [IAM overview](https://cloud.ibm.com/iam/overview).
3. Click **API Keys**.
4. Click **Create**.
5. Enter a **Name** and click **Create**.
6. Copy or Download the API Key.

### [1.2] New Secret Manager instance

1. Go to the [Secrets Manager](https://cloud.ibm.com/catalog/services/secrets-manager).
2. Select a plan.
3. Click **Create**.

### [1.3] Accessing an existing secrets manager instance
1. Go to your [Resources list](https://cloud.ibm.com/resources).
2. On the navigation menu, click **Resource list** > **Security** > **Secrets Manager**. 
3. Select Secrets Manager instance.


## [2] Secret types and mapping

Cloud Pak Secret Type | IBM Cloud Secrets Manager Secret Type | How to store a secret
---|---|---
Username and password | Choose type `User credentials`<br><br> |  Store value for the following attributes<br>1. username<br>2. password
Key | Choose type `Other / arbitrary value`|
TLS certificate	| Choose type `Certificates / Imported certs`|
Custom | Choose type `Key-Value`|
