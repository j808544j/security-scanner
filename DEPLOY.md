# Production deployment design

## Hosting on AWS

Run the Nginx dashboard and FastAPI as two ECS Fargate services in private subnets. An HTTPS Application Load Balancer with an ACM certificate forwards traffic to the dashboard. Nginx proxies same-origin `/api/` requests to the API over private service discovery. Restrict ingress to approved networks and require an OIDC session at the load balancer. Allow only the dashboard to reach the API, and only the API to reach the database. Use VPC endpoints for ECR, S3, Secrets Manager, and CloudWatch Logs where practical.

Use private RDS PostgreSQL with encryption, TLS, backups, and point-in-time recovery. Port the SQLite store before deployment and run migrations with a separate role. Give the application role access to scan and finding data. Keep one API task with one process under the current scan ownership model. During a rollout, stop the old task before starting the replacement so startup recovery can mark interrupted scans as failed without interfering with an active task. This accepts a brief API outage at rollout. Independent workers and durable scan ownership would be prerequisites for multiple API tasks. [Scan execution decision](docs/adr/0001-in-process-scan-execution.md)

Place versioned inventory snapshots in an encrypted private S3 bucket. Stage one pinned version at `INVENTORY_PATH` when the API task starts and grant its task role read access to that object and any required KMS decrypt permission. Inject the database credentials from Secrets Manager. Scope the execution role to image pulls, logs, and access to the configured secret. Send structured container logs to CloudWatch with a retention policy. Alert on unhealthy targets, failed scans, and sustained increases in CANNOT_SCAN findings. Leave inventory records and credentials out of logs.

GitHub Actions runs lint, type checks, tests, and the Compose smoke test before deployment. A protected GitHub environment uses GitHub OIDC to assume a short-lived AWS deployment role. Restrict the role's trust to this repository and environment, and scope its permissions to the two ECR repositories, named ECS services, and the task roles it must pass. Publish both tested images by commit SHA and deploy their digests through ECS. Roll back to the previous task definitions if health checks fail. [GitHub OIDC configuration for AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)

## Read-only inventory permissions

A future live collector would use separate provider identities scoped to the accounts, subscriptions, and projects it scans. The snapshot application needs only the snapshot access described above. The permissions below cover the fields used by this catalog.

| Checks | Collector permissions |
| --- | --- |
| AWS-S3-01 | `s3:ListAllMyBuckets` for discovery and `s3:GetBucketPublicAccessBlock` for the scanned buckets. [S3 API permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html) |
| AWS-EC2-01 and AWS-RDS-01 | `ec2:DescribeSecurityGroups` and `rds:DescribeDBInstances` in configured regions. [EC2 authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html), [RDS authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonrds.html) |
| AWS-IAM-01 and AWS-IAM-02 | `iam:ListUsers`, `iam:GetLoginProfile`, `iam:ListMFADevices`, and `iam:ListAccessKeys`. Scope per-user reads to the scanned users where known. [IAM authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagementiam.html) |
| AZ-STG-01 and AZ-NSG-01 | `Microsoft.Storage/storageAccounts/read` and `Microsoft.Network/networkSecurityGroups/read` at the scanned subscription or resource-group scope. Read the inline NSG rules from the NSG response. [Azure Storage operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/storage), [Azure Network operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/networking) |
| GCP-GCS-01 and GCP-GCS-02 | `storage.buckets.list` for discovery and metadata, and `storage.buckets.getIamPolicy` for each scanned bucket. Add `storage.buckets.get` if the collector reads metadata per bucket. [Cloud Storage permissions](https://docs.cloud.google.com/storage/docs/access-control/iam-permissions) |
| GCP-VPC-01 | `compute.firewalls.list` on each scanned project. [Compute Engine firewall list](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls/list) |
