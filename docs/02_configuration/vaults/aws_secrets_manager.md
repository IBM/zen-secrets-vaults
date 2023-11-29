# AWS Secrets Manager

To store secrets on AWS Secrets Manager, follow these instructions.

## [1] AWS Setup

### [1.1] Create an Amazon Web Services account
1. [Sign up for an AWS account](https://portal.aws.amazon.com/billing/signup).
2. Go to [secret manager console](https://console.aws.amazon.com/secretsmanager/).


## [2] Secret types and mapping

1. Go to [secret manager console](https://console.aws.amazon.com/secretsmanager/).
2. On the left side menu > **secrets**.
3. From top right of the page, select **region**.
4. Store the secret.

Cloud Pak Secret Type | AWS Secrets Manager Secret Type | How to store a secret
---|---|---
Username and password | Choose any of the following <br>1. Amazon RDS database<br>2. Amazon  Document DB<br>3. Amazon  Redshift database<br>4. Other database<br><br> | Store a secret with the following keys<br>1. username<br>2. password
Key | Choose - Other type of secret<br> | Store a secret with the following keys<br>1. key
Token | Choose - Other type of secret<br> | Store a secret with the following keys<br>1. token
TLS certificate	| Choose - Other type of secret<br><br> | Store a secret with the following keys<br>1. cert<br>2. key(optional)
Custom | Choose - Other type of secret | Store a secret with the user-defined keys
