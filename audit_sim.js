/**
 * Simulated Audit Engine for AWS and Azure
 * Generates realistic security findings for demo purposes.
 */

async function runSimulatedAudit(platform, credentials, log) {
    log(`Initializing secure session with ${platform.toUpperCase()}...`);
    await sleep(800);
    
    log(`Bypassing identity federation for ${platform.toUpperCase()}...`);
    await sleep(600);
    
    log(`Enumerating ${platform.toUpperCase()} infrastructure assets...`);
    log("PROGRESS: 10%");
    await sleep(1500);

    const results = {
        platform: platform.toUpperCase(),
        projectId: credentials.accountName || `${platform}-demo-project`,
        projectMetadata: {
            name: credentials.projectName || `${platform.toUpperCase()} Enterprise Cluster`,
            id: credentials.accountName || "audit-scope-simulation"
        },
        timestamp: new Date().toISOString(),
        services: {}
    };

    const platformLower = platform.toLowerCase();
    if (platformLower === 'aws') {
        results.services = await generateAWSSimulation(log);
    } else if (platformLower === 'azure') {
        results.services = await generateAzureSimulation(log);
    } else if (platformLower === 'gcp') {
        results.services = await generateGCPSimulation(log);
    }

    log(`Audit compilation for ${platform.toUpperCase()} complete.`);
    return results;
}

async function generateAWSSimulation(log) {
    log("Scanning AWS S3 Buckets...");
    log("PROGRESS: 30%");
    await sleep(800);
    log("Checking IAM User MFA status...");
    log("PROGRESS: 60%");
    await sleep(800);
    log("Auditing EC2 Security Groups...");
    log("PROGRESS: 90%");
    await sleep(800);
    
    return {
        "storage": {
            summary: { high: 2, medium: 2, low: 2, secure: 5 },
            vulnerabilities: [
                { asset: "prod-static-assets", description: "Public Read access enabled on bucket — all objects publicly readable", severity: "Critical", remediation: "Enable 'Block all public access' in S3 settings." },
                { asset: "backup-vault-01", description: "Default encryption (SSE-S3) not enforced", severity: "High", remediation: "Enable default encryption with AES-256 or KMS." },
                { asset: "audit-logs-archive", description: "S3 versioning not enabled — risk of accidental deletion", severity: "Low", remediation: "Enable versioning for the bucket." },
                { asset: "dev-artifacts-bucket", description: "S3 access logging disabled", severity: "Low", remediation: "Enable server access logging." }
            ],
            inventory: [
                { category: "Storage", id: "prod-static-assets", type: "S3 Bucket", details: "Region: us-east-1", remarks: "Public Accessible" },
                { category: "Storage", id: "backup-vault-01", type: "S3 Bucket", details: "Region: us-west-2", remarks: "No Encryption" },
                { category: "Storage", id: "audit-logs-archive", type: "S3 Bucket", details: "Region: us-east-1", remarks: "Active" },
                { category: "Storage", id: "dev-artifacts-bucket", type: "S3 Bucket", details: "Region: ap-south-1", remarks: "Active" }
            ]
        },
        "compute": {
            summary: { high: 3, medium: 4, low: 3, secure: 10 },
            vulnerabilities: [
                { asset: "web-server-fleet (sg-0a1b2c)", description: "Security Group allows inbound SSH (22) from 0.0.0.0/0", severity: "High", remediation: "Restrict SSH to known IP ranges or use SSM Session Manager." },
                { asset: "ami-0c55b159cbfafe1f0", description: "Custom AMI is publicly accessible", severity: "High", remediation: "Make the AMI private." },
                { asset: "i-0987654321abcdef0 (web-srv-01)", description: "IMDSv1 enabled — vulnerable to SSRF attacks", severity: "High", remediation: "Set HttpTokens=required to enforce IMDSv2." },
                { asset: "vol-01a2b3c4d5e6f7890", description: "EBS volume is not encrypted", severity: "Medium", remediation: "Create encrypted snapshot and replace volume." },
                { asset: "i-0987654321abcdef0 (web-srv-01)", description: "Public IP 54.21.34.12 assigned", severity: "Medium", remediation: "Use private subnets with NAT for outbound traffic." },
                { asset: "ecs-cluster-prod", description: "ECS Container Insights not enabled", severity: "Low", remediation: "Enable Container Insights for observability." }
            ],
            inventory: [
                { category: "EC2", id: "i-0987654321abcdef0", type: "t3.medium", details: "AZ: us-east-1a, IP: 54.21.34.12", remarks: "Running" },
                { category: "EC2", id: "i-0abc1234567890def", type: "r5.xlarge", details: "AZ: us-east-1b, Private", remarks: "Running" },
                { category: "Security Group", id: "sg-0a1b2c3d4e5f", type: "Security Group", details: "web-server-fleet", remarks: "SSH Open" },
                { category: "ECS", id: "ecs-cluster-prod", type: "ECS Cluster", details: "Tasks: 8", remarks: "Active" },
                { category: "EKS", id: "eks-prod-cluster", type: "EKS v1.27", details: "Endpoint: Public", remarks: "Running" },
                { category: "EBS", id: "vol-01a2b3c4d5e6f7890", type: "gp3 (100GB)", details: "AZ: us-east-1a", remarks: "Unencrypted" }
            ]
        },
        "identity-access": {
            summary: { high: 3, medium: 3, low: 2, secure: 8 },
            vulnerabilities: [
                { asset: "Root Account", description: "MFA not enabled on root credentials", severity: "Critical", remediation: "Enable hardware or virtual MFA for root account." },
                { asset: "Root Account", description: "Root account has active access keys", severity: "Critical", remediation: "Delete root access keys immediately." },
                { asset: "admin-ratan", description: "IAM user has no MFA device", severity: "High", remediation: "Enforce MFA for all IAM users." },
                { asset: "deploy-automation", description: "Access key is 127 days old (> 90 days)", severity: "High", remediation: "Rotate access keys every 90 days." },
                { asset: "Password Policy", description: "No account password policy configured", severity: "High", remediation: "Configure strong password policy with complexity requirements." },
                { asset: "IAM Policies", description: "8 entities have AdministratorAccess — overly permissive", severity: "Medium", remediation: "Apply principle of least privilege." }
            ],
            inventory: [
                { category: "IAM", id: "admin-ratan", type: "IAM User", details: "Last Login: 2 days ago", remarks: "Privileged" },
                { category: "IAM", id: "deploy-automation", type: "IAM User", details: "Last Login: 7 days ago", remarks: "AccessKey Old" },
                { category: "IAM", id: "ec2-instance-role", type: "IAM Role", details: "Service: ec2.amazonaws.com", remarks: "Instance Role" },
                { category: "IAM", id: "ci-cd-role", type: "IAM Role", details: "Service: codebuild.amazonaws.com", remarks: "CI/CD Role" }
            ]
        },
        "network": {
            summary: { high: 1, medium: 2, low: 3, secure: 6 },
            vulnerabilities: [
                { asset: "vpc-0a1b2c3d4e5f (default)", description: "Default VPC in use — resources should use custom VPCs", severity: "Low", remediation: "Create a custom VPC and migrate workloads." },
                { asset: "vpc-0123456789abcdef0", description: "VPC Flow Logs not enabled", severity: "Medium", remediation: "Enable VPC Flow Logs to CloudWatch Logs or S3." },
                { asset: "nacl-prod", description: "NACL allows ALL inbound traffic from 0.0.0.0/0", severity: "High", remediation: "Restrict NACL inbound rules to required ports only." },
                { asset: "d123456789.cloudfront.net", description: "CloudFront using outdated TLS v1.0", severity: "High", remediation: "Set minimum TLS to TLSv1.2_2021." }
            ],
            inventory: [
                { category: "VPC", id: "vpc-0a1b2c3d4e5f", type: "Default VPC", details: "CIDR: 172.31.0.0/16", remarks: "Default" },
                { category: "VPC", id: "vpc-0123456789abcdef0", type: "Custom VPC", details: "CIDR: 10.0.0.0/16", remarks: "Production" },
                { category: "Route 53", id: "example.com.", type: "Public Hosted Zone", details: "Records: 12", remarks: "DNS Zone" },
                { category: "CloudFront", id: "d123456789.cloudfront.net", type: "CloudFront Distribution", details: "Status: Deployed", remarks: "CDN" }
            ]
        },
        "databases": {
            summary: { high: 2, medium: 3, low: 2, secure: 7 },
            vulnerabilities: [
                { asset: "prod-mysql-db", description: "RDS instance is publicly accessible", severity: "Critical", remediation: "Disable public accessibility and use private subnets." },
                { asset: "prod-mysql-db", description: "RDS backup retention is 1 day (< 7 days)", severity: "Medium", remediation: "Set backup retention to 7+ days." },
                { asset: "prod-mysql-db", description: "Multi-AZ not enabled — single point of failure", severity: "Low", remediation: "Enable Multi-AZ for production databases." },
                { asset: "redis-session-cache", description: "ElastiCache transit encryption not enabled", severity: "Medium", remediation: "Enable in-transit encryption (TLS)." },
                { asset: "user-events-table", description: "DynamoDB PITR (Point-in-Time Recovery) not enabled", severity: "Medium", remediation: "Enable PITR for DynamoDB data protection." }
            ],
            inventory: [
                { category: "RDS", id: "prod-mysql-db", type: "MySQL 8.0 (db.t3.medium)", details: "Public IP: Yes", remarks: "Production DB" },
                { category: "RDS", id: "reporting-postgres", type: "PostgreSQL 14 (db.r5.large)", details: "Multi-AZ: Yes", remarks: "Encrypted" },
                { category: "ElastiCache", id: "redis-session-cache", type: "Redis 7.0 (cache.t3.micro)", details: "Nodes: 1", remarks: "No TLS" },
                { category: "DynamoDB", id: "user-events-table", type: "DynamoDB Table", details: "Items: 4.2M", remarks: "No PITR" }
            ]
        },
        "serverless": {
            summary: { high: 2, medium: 2, low: 2, secure: 6 },
            vulnerabilities: [
                { asset: "data-processor-lambda", description: "Lambda function has public invocation policy (Principal: *)", severity: "Critical", remediation: "Restrict Lambda resource policy to known callers." },
                { asset: "api-handler-lambda", description: "Deprecated runtime: nodejs12.x", severity: "High", remediation: "Update to nodejs20.x or later." },
                { asset: "image-resizer-fn", description: "Lambda not deployed in a VPC", severity: "Low", remediation: "Deploy Lambda in a VPC for network isolation." }
            ],
            inventory: [
                { category: "Lambda", id: "data-processor-lambda", type: "Lambda (python3.9)", details: "Memory: 512MB", remarks: "Public" },
                { category: "Lambda", id: "api-handler-lambda", type: "Lambda (nodejs12.x)", details: "Memory: 128MB", remarks: "Deprecated Runtime" },
                { category: "Lambda", id: "image-resizer-fn", type: "Lambda (python3.10)", details: "Memory: 1024MB", remarks: "No VPC" }
            ]
        },
        "loadbalancing": {
            summary: { high: 1, medium: 1, low: 2, secure: 4 },
            vulnerabilities: [
                { asset: "prod-alb-main", description: "ALB has HTTP listener but no HTTPS — traffic unencrypted", severity: "High", remediation: "Add HTTPS listener and redirect HTTP to HTTPS." },
                { asset: "internal-nlb-01", description: "NLB access logging not enabled", severity: "Low", remediation: "Enable access logs to S3 for traffic monitoring." },
                { asset: "legacy-classic-lb", description: "Classic ELB in use — deprecated, migrate to ALB/NLB", severity: "Low", remediation: "Migrate to Application or Network Load Balancer." }
            ],
            inventory: [
                { category: "ELB", id: "prod-alb-main", type: "ALB (internet-facing)", details: "AZ: us-east-1a, us-east-1b", remarks: "HTTP Only" },
                { category: "ELB", id: "internal-nlb-01", type: "NLB (internal)", details: "AZ: us-east-1a", remarks: "Encrypted" },
                { category: "ELB", id: "legacy-classic-lb", type: "Classic ELB", details: "Scheme: internet-facing", remarks: "Deprecated" }
            ]
        },
        "operations": {
            summary: { high: 2, medium: 2, low: 2, secure: 5 },
            vulnerabilities: [
                { asset: "CloudTrail us-west-2", description: "No CloudTrail configured in us-west-2", severity: "High", remediation: "Enable CloudTrail in all regions." },
                { asset: "main-trail", description: "CloudTrail log file validation disabled", severity: "Medium", remediation: "Enable log file validation to detect tampering." },
                { asset: "main-trail", description: "CloudTrail logs not encrypted with KMS", severity: "Low", remediation: "Configure SSE-KMS encryption for trail logs." },
                { asset: "prod-app-logs", description: "CloudWatch Log Group has no retention policy (never expires)", severity: "Low", remediation: "Set a 90-day retention policy." },
                { asset: "kms-app-key-01", description: "KMS customer-managed key rotation not enabled", severity: "Medium", remediation: "Enable automatic annual key rotation." }
            ],
            inventory: [
                { category: "CloudTrail", id: "main-trail", type: "CloudTrail", details: "Bucket: audit-logs-prod", remarks: "Active" },
                { category: "CloudWatch", id: "prod-alarms", type: "CloudWatch Alarms", details: "Total: 12, OK: 10", remarks: "Monitoring" },
                { category: "Log Group", id: "prod-app-logs", type: "CloudWatch Logs", details: "Retention: Never Expire", remarks: "Cost Risk" },
                { category: "KMS", id: "kms-app-key-01", type: "KMS CMK", details: "Usage: ENCRYPT_DECRYPT", remarks: "No Rotation" }
            ]
        },
        "artifacts": {
            summary: { high: 0, medium: 2, low: 1, secure: 3 },
            vulnerabilities: [
                { asset: "app-container-repo", description: "ECR scan on push is disabled — images not checked for CVEs", severity: "Medium", remediation: "Enable scan on push for automated vulnerability detection." },
                { asset: "base-images-repo", description: "ECR repo not encrypted with KMS", severity: "Low", remediation: "Configure KMS encryption for ECR repositories." }
            ],
            inventory: [
                { category: "ECR", id: "app-container-repo", type: "ECR Repository", details: "URI: 123456789.dkr.ecr.us-east-1.amazonaws.com", remarks: "Scan Disabled" },
                { category: "ECR", id: "base-images-repo", type: "ECR Repository", details: "Format: DOCKER", remarks: "No KMS" },
                { category: "ECR", id: "helm-charts-repo", type: "ECR Repository (OCI)", details: "Format: Helm", remarks: "Secure" }
            ]
        },
        "analytics": {
            summary: { high: 0, medium: 1, low: 3, secure: 5 },
            vulnerabilities: [
                { asset: "payment-events-topic", description: "SNS topic not encrypted with KMS", severity: "Low", remediation: "Enable SSE-KMS for SNS topic." },
                { asset: "order-processing-queue", description: "SQS queue not encrypted", severity: "Low", remediation: "Enable SSE or KMS encryption for SQS." },
                { asset: "order-processing-queue", description: "SQS queue has no Dead Letter Queue (DLQ)", severity: "Medium", remediation: "Configure a DLQ to handle failed message processing." }
            ],
            inventory: [
                { category: "SNS", id: "payment-events-topic", type: "SNS Topic", details: "Subscriptions: 3", remarks: "No KMS" },
                { category: "SQS", id: "order-processing-queue", type: "SQS Queue", details: "Messages: 42", remarks: "No DLQ" },
                { category: "SQS", id: "notifications-dlq", type: "SQS Dead Letter Queue", details: "Messages: 0", remarks: "Secure" }
            ]
        },
        "aiml": {
            summary: { high: 2, medium: 0, low: 0, secure: 1 },
            vulnerabilities: [
                { asset: "GuardDuty us-west-2", description: "GuardDuty not enabled in us-west-2", severity: "High", remediation: "Enable GuardDuty in all regions for threat detection." },
                { asset: "GuardDuty us-east-1", description: "3 HIGH-severity GuardDuty findings detected", severity: "High", remediation: "Review and remediate GuardDuty findings in the console." }
            ],
            inventory: [
                { category: "Security", id: "guardduty-us-east-1", type: "GuardDuty Detector", details: "Findings: 3 High", remarks: "Enabled" },
                { category: "Security", id: "guardduty-us-west-2", type: "GuardDuty Detector", details: "Status: Disabled", remarks: "⚠️ Disabled" }
            ]
        }
    };
}

async function generateAzureSimulation(log) {
    log("Scanning Azure Virtual Machines...");
    log("PROGRESS: 30%");
    await sleep(800);
    log("Checking Azure AD (Entra ID) compliance...");
    log("PROGRESS: 60%");
    await sleep(800);
    log("Auditing Storage Accounts...");
    log("PROGRESS: 90%");
    await sleep(800);

    return {
        "compute": {
            summary: { critical: 1, high: 1, medium: 2, low: 4 },
            vulnerabilities: [
                { asset: "vm-win-payroll", description: "Missing critical OS security updates", severity: "CRITICAL", remediation: "Apply pending security patches." },
                { asset: "vm-linux-proxy", description: "Public IP lacks NSG protection", severity: "HIGH", remediation: "Apply Network Security Group." }
            ],
            inventory: [
                { category: "Compute", id: "vm-win-payroll", type: "Standard_D2s_v3", details: "OS: Windows Server", remarks: "Vulnerable" },
                { category: "Compute", id: "vm-worker-pool", type: "Standard_B2s", details: "OS: Ubuntu 22.04", remarks: "Clean" }
            ]
        },
        "iam": {
            summary: { critical: 0, high: 2, medium: 1, low: 5 },
            vulnerabilities: [
                { asset: "Conditional Access", description: "Identity protection policies not enforced", severity: "HIGH", remediation: "Configure CA policies." }
            ],
            inventory: [
                { category: "Identity", id: "Global Admin", type: "High Privilege", details: "1 Active", remarks: "Monitored" },
                { category: "Identity", id: "B2B Guest Users", type: "Guest", details: "14 Users", remarks: "Review Req" }
            ]
        },
        "storage": {
            summary: { critical: 1, high: 0, medium: 3, low: 2 },
            vulnerabilities: [
                { asset: "stfinsysdata", description: "Minimum TLS version not set to 1.2", severity: "CRITICAL", remediation: "Enforce TLS 1.2 for all requests." }
            ],
            inventory: [
                { category: "Storage", id: "stfinsysdata", type: "Storage Account (V2)", details: "Region: West Europe", remarks: "Encrypted" }
            ]
        },
        "serverless": {
            summary: { critical: 0, high: 1, medium: 1, low: 2 },
            vulnerabilities: [
                { asset: "payment-webhook", description: "Function App has authentication disabled", severity: "HIGH", remediation: "Enable App Service Authentication." },
                { asset: "report-gen-fn", description: "Function uses public storage for artifacts", severity: "MEDIUM", remediation: "Secure the background storage account." }
            ],
            inventory: [
                { category: "Serverless", id: "payment-webhook", type: "Azure Function", details: "Tier: Elastic Premium", remarks: "Auth Off" },
                { category: "Serverless", id: "report-gen-fn", type: "Azure Function", details: "Runtime: Python 3.8", remarks: "Vulnerable" }
            ]
        }
    };
}

async function generateGCPSimulation(log) {
    log("Scanning Compute Engine instances...");
    log("PROGRESS: 20%");
    await sleep(800);
    log("Analyzing IAM Service Account permissions...");
    log("PROGRESS: 50%");
    await sleep(800);
    log("Checking Cloud Storage bucket ACLs...");
    log("PROGRESS: 75%");
    await sleep(800);
    await sleep(800);
    log("Verifying GKE Cluster security config...");
    log("PROGRESS: 85%");
    await sleep(800);
    log("Scanning Artifact Registry repositories...");
    log("PROGRESS: 95%");
    await sleep(800);

    return {
        "compute": {
            summary: { critical: 0, high: 2, medium: 1, low: 4 },
            vulnerabilities: [
                { asset: "instance-1-prod", description: "OS Login not enabled", severity: "HIGH", remediation: "Enable OS Login in metadata." },
                { asset: "bastion-host", description: "Public IP attached", severity: "HIGH", remediation: "Use IAP for access instead of Public IP." }
            ],
            inventory: [
                { category: "Compute", id: "instance-1-prod", type: "e2-medium", details: "Zone: us-central1-a", remarks: "Running" },
                { category: "Compute", id: "bastion-host", type: "f1-micro", details: "Zone: us-central1-a", remarks: "Public Accessible" }
            ]
        },
        "storage": {
            summary: { critical: 1, high: 0, medium: 1, low: 2 },
            vulnerabilities: [
                { asset: "legacy-backups-2023", description: "Bucket is publically readable", severity: "CRITICAL", remediation: "Remove 'allUsers' from IAM policy." }
            ],
            inventory: [
                { category: "Storage", id: "legacy-backups-2023", type: "Standard", details: "Loc: Multi-Region", remarks: "Public Risk" },
                { category: "Storage", id: "app-assets-prod", type: "Standard", details: "Loc: US", remarks: "Secure" }
            ]
        },
        "iam": {
            summary: { high: 0, medium: 2, low: 3, secure: 1 },
            vulnerabilities: [
                { asset: "Project IAM", description: "Audit logging is not configured for all services.", severity: "MEDIUM", remediation: "Configure Cloud Audit Logs." },
                { asset: "admin-user@example.com", description: "User has primitive role: Owner.", severity: "MEDIUM", remediation: "Use granular IAM roles." }
            ],
            inventory: [
                { category: "Identity", id: "admin-user@example.com", type: "Human User", details: "Role: Owner", remarks: "Privileged" },
                { category: "Identity", id: "madhuri.m@cloudambassadors.com", type: "Human User", details: "Role: Viewer", remarks: "Active" },
                { category: "Identity", id: "security-auditor@example.com", type: "Human User", details: "Role: SecurityReviewer", remarks: "Compliance" },
                { category: "Governance", id: "Project IAM", type: "Policy", details: "Project-level", remarks: "Partial" }
            ]
        },
        "serviceaccounts": {
            summary: { high: 2, medium: 1, low: 0, secure: 2 },
            vulnerabilities: [
                { asset: "deploy-svc-acct@demo.com", description: "Key not rotated in 90 days", severity: "HIGH", remediation: "Rotate service account keys." },
                { asset: "terraform-admin@demo.com", description: "Service Account has primitive role: Editor.", severity: "HIGH", remediation: "Use granular IAM roles." }
            ],
            inventory: [
                { category: "Identity", id: "deploy-svc-acct@demo.com", type: "Service Account", details: "dkey-39f...", remarks: "Old Key" },
                { category: "Identity", id: "terraform-admin@demo.com", type: "Service Account", details: "Primitive: Editor", remarks: "Over-privileged" },
                { category: "Identity", id: "cloud-run-runtime@demo.com", type: "Service Account", details: "Standard: Managed", remarks: "Secure" },
                { category: "Identity", id: "88273645-compute@developer.gserviceaccount.com", type: "Default Service Account", details: "Compute Engine Default", remarks: "High Risk" }
            ]
        },
        "databases": {
            summary: { critical: 1, high: 1, medium: 2, low: 2 },
            vulnerabilities: [
                { asset: "prod-db-master", description: "Cloud SQL whitelists all public IPs (0.0.0.0/0)", severity: "CRITICAL", remediation: "Remove 0.0.0.0/0 from authorized networks." },
                { asset: "prod-db-master", description: "SSL connections are not required", severity: "HIGH", remediation: "Enforce SSL for all database connections." },
                { asset: "Firestore/(default)", description: "Point-in-time recovery is disabled", severity: "MEDIUM", remediation: "Enable PITR for Cloud Firestore." },
                { asset: "customer-records", description: "Automated backups are disabled", severity: "MEDIUM", remediation: "Enable automated backups in database settings." }
            ],
            inventory: [
                { category: "Databases", id: "prod-db-master", type: "Cloud SQL (POSTGRES_14)", details: "Region: us-central1, Tier: db-f1-micro", remarks: "Public IP Enabled" },
                { category: "Databases", id: "(default)", type: "Firestore (Native)", details: "Location: nam5, State: READY", remarks: "NoSQL Store" },
                { category: "Databases", id: "spanner-main", type: "Cloud Spanner", details: "Nodes: 1, State: READY", remarks: "Relational" }
            ]
        },
        "serverless": {
            summary: { critical: 1, high: 1, medium: 2, low: 1 },
            vulnerabilities: [
                { asset: "billing-api-service", description: "Cloud Run service is publicly accessible (allUsers)", severity: "CRITICAL", remediation: "Remove 'allUsers' from IAM policy." },
                { asset: "process-payment-fn", description: "Function uses deprecated nodejs14 runtime", severity: "HIGH", remediation: "Update to nodejs20 or later." },
                { asset: "image-resize-run", description: "Ingress settings set to ALLOW_ALL", severity: "MEDIUM", remediation: "Restrict ingress to internal/load-balancer only." },
                { asset: "metadata-fetch-fn", description: "Potential secret found in env var: API_KEY", severity: "MEDIUM", remediation: "Use Secret Manager for sensitive values." }
            ],
            inventory: [
                { category: "Serverless", id: "billing-api-service", type: "Cloud Run", details: "Region: us-central1", remarks: "Public" },
                { category: "Serverless", id: "process-payment-fn", type: "Cloud Function", details: "Runtime: nodejs14", remarks: "Deprecated" },
                { category: "Serverless", id: "image-resize-run", type: "Cloud Run", details: "Region: us-east1", remarks: "Internal Only" }
            ]
        },
        "devops": {
            summary: { critical: 1, high: 2, medium: 2, low: 3 },
            vulnerabilities: [
                { asset: "worker-pool-vpc", description: "Worker pool not connected to peered network.", severity: "MEDIUM", remediation: "Configure private network peering for worker pool." },
                { asset: "primary-build-trigger", description: "Trigger uses default Cloud Build service account", severity: "HIGH", remediation: "Use a custom service account with minimal IAM roles." },
                { asset: "frontend-deploy-pipeline", description: "Build logs are not encrypted with CMEK", severity: "MEDIUM", remediation: "Configure a CMEK-encrypted Cloud Storage bucket for build logs." },
                { asset: "legacy-build-config", description: "Unrestricted build triggers detected", severity: "CRITICAL", remediation: "Restrict triggers to specific branches and use approval gates." }
            ],
            inventory: [
                { category: "CloudBuild", id: "primary-build-trigger", type: "Cloud Build Trigger", details: "Repo: GitHub, State: ENABLED", remarks: "Default SA" },
                { category: "CloudBuild", id: "frontend-deploy-pipeline", type: "Cloud Build Trigger", details: "Repo: GitLab, State: ENABLED", remarks: "No CMEK" },
                { category: "CloudBuild", id: "backend-build-v2", type: "Cloud Build Trigger", details: "Repo: Cloud Source, State: ENABLED", remarks: "Secure" },
                { category: "CloudBuild", id: "release-orchestrator", type: "Cloud Build Pipeline", details: "Status: Success", remarks: "Multi-stage" },
                { category: "CloudBuild", id: "worker-pool-vpc", type: "Cloud Build WorkerPool", details: "VPC: production-vpc", remarks: "Secure Peering" },
                { category: "CloudBuild", id: "worker pools", type: "Cloud Build WorkerPool", details: "Default Pool", remarks: "No Private Pools" }
            ]
        },
        "artifacts": {
            summary: { critical: 1, high: 0, medium: 3, low: 5 },
            vulnerabilities: [
                { asset: "container-images-prod", description: "Repository is publicly accessible", severity: "CRITICAL", remediation: "Remove 'allUsers' from IAM policy." },
                { asset: "maven-lib-repo", description: "Customer-Managed Encryption Keys (CMEK) not enabled", severity: "MEDIUM", remediation: "Enable CMEK for repository encryption." },
                { asset: "npm-internal-cache", description: "Vulnerability scanning is disabled", severity: "MEDIUM", remediation: "Enable automatic vulnerability scanning for repositories." }
            ],
            inventory: [
                { category: "Registry", id: "container-images-prod", type: "Artifact Registry", details: "Format: DOCKER, Loc: us-central1", remarks: "Public Accessible" },
                { category: "Registry", id: "maven-lib-repo", type: "Artifact Registry", details: "Format: MAVEN, Loc: us-east1", remarks: "Not Encrypted" },
                { category: "Registry", id: "npm-packages-internal", type: "Artifact Registry", details: "Format: NPM, Loc: us-central1", remarks: "Secure" },
                { category: "Registry", id: "python-wheels-repo", type: "Artifact Registry", details: "Format: PYTHON, Loc: us-west1", remarks: "Private" }
            ]
        }
    };
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { runSimulatedAudit };
