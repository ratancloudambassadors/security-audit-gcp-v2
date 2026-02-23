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

    if (platform === 'aws') {
        results.services = await generateAWSSimulation(log);
    } else if (platform === 'azure') {
        results.services = await generateAzureSimulation(log);
    } else if (platform === 'gcp') {
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
            summary: { high: 2, medium: 1, low: 3, secure: 5 },
            vulnerabilities: [
                { asset: "prod-static-assets", description: "Public Read access enabled on bucket", severity: "Critical", remediation: "Disable public access in bucket policy." },
                { asset: "backup-vault-01", description: "Default encryption (SSE-S3) not enforced", severity: "High", remediation: "Enable default encryption." }
            ],
            inventory: [
                { category: "Storage", id: "prod-static-assets", type: "S3 Bucket", details: "Region: us-east-1, Size: 1.2TB", remarks: "Public Accessible" },
                { category: "Storage", id: "audit-logs-2024", type: "S3 Bucket", details: "Region: us-east-1, Size: 450GB", remarks: "Encrypted" }
            ]
        },
        "compute": {
            summary: { high: 1, medium: 3, low: 5, secure: 8 },
            vulnerabilities: [
                { asset: "web-server-fleet", description: "Security Group allows inbound SSH (22) from 0.0.0.0/0", severity: "High", remediation: "Restrict SSH to known IP ranges." },
                { asset: "ami-0c55b159", description: "Custom AMI is publicly accessible.", severity: "High", remediation: "Make the AMI private." }
            ],
            inventory: [
                { category: "Compute", id: "web-srv-01", type: "t3.medium", details: "Public IP: 54.21.34.12", remarks: "Running" },
                { category: "Compute", id: "db-instance-primary", type: "r5.xlarge", details: "Private IP: 10.0.1.44", remarks: "Running" }
            ]
        },
        "iam": {
            summary: { high: 1, medium: 2, low: 10, secure: 15 },
            vulnerabilities: [
                { asset: "Root Account", description: "MFA not enabled on root credentials", severity: "Critical", remediation: "Enable hardware or virtual MFA for root." },
                { asset: "admin-ratan", description: "Privileged user has no MFA enabled.", severity: "Critical", remediation: "Enable MFA immediately." }
            ],
            inventory: [
                { category: "Identity", id: "admin-ratan", type: "IAM User", details: "Last Login: 2 days ago", remarks: "Privileged" },
                { category: "Identity", id: "dev-service-account", type: "Access Key", details: "Rotating: Yes", remarks: "Secure" }
            ]
        },
        "devops": {
            summary: { high: 1, medium: 2, low: 3, secure: 4 },
            vulnerabilities: [
                { asset: "primary-build-proj", description: "Potential secret found in plaintext environment variable: AWS_SECRET_KEY", severity: "High", remediation: "Use Secrets Manager." },
                { asset: "release-pipeline", description: "Pipeline artifact store not encrypted with KMS.", severity: "Medium", remediation: "Configure KMS encryption." }
            ],
            inventory: [
                { category: "CloudBuild", id: "primary-build-proj", type: "CodeBuild Project", details: "Runtime: LINUX_CONTAINER", remarks: "Vulnerable Env" },
                { category: "CloudBuild", id: "release-pipeline", type: "CodePipeline", details: "Stages: 4", remarks: "Standard" }
            ]
        },
        "artifacts": {
            summary: { high: 0, medium: 1, low: 2, secure: 3 },
            vulnerabilities: [
                { asset: "app-container-repo", description: "ECR scan on push is disabled.", severity: "Medium", remediation: "Enable scan on push." }
            ],
            inventory: [
                { category: "Registry", id: "app-container-repo", type: "ECR Repository", details: "URI: 123456789.dkr.ecr.us-east-1.amazonaws.com", remarks: "Scan Disabled" }
            ]
        },
        "serverless": {
            summary: { high: 1, medium: 2, low: 1, secure: 5 },
            vulnerabilities: [
                { asset: "data-processor-lambda", description: "Lambda function is publicly accessible", severity: "Critical", remediation: "Remove public trigger." },
                { asset: "api-handler-lambda", description: "Function uses outdated nodejs12.x runtime", severity: "Medium", remediation: "Update to nodejs20.x." }
            ],
            inventory: [
                { category: "Serverless", id: "data-processor-lambda", type: "AWS Lambda", details: "Region: us-east-1", remarks: "Public" },
                { category: "Serverless", id: "api-handler-lambda", type: "AWS Lambda", details: "Runtime: nodejs12.x", remarks: "Deprecated" }
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
