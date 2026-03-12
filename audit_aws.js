const AWS = require('aws-sdk');

async function runAWSAudit(accessKeyId, secretAccessKey, region = 'us-east-1', logCallback) {
    const baseConfig = {
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
        region: region === 'all' ? 'us-east-1' : region
    };

    logCallback("Authenticating with AWS Secure Session...");
    
    // Determine regions to scan FIRST
    let regionsToScan = [region];
    if (region === 'all') {
        try {
            logCallback("Discovering all active AWS regions...");
            const ec2Global = new AWS.EC2(baseConfig);
            const data = await ec2Global.describeRegions({ Filters: [{ Name: 'opt-in-status', Values: ['opt-in-not-required', 'opted-in'] }] }).promise();
            regionsToScan = data.Regions.map(r => r.RegionName);
            logCallback(`Identified ${regionsToScan.length} active regions.`);
        } catch (e) {
            logCallback(`Region discovery failed: ${e.message}. Using default.`);
            regionsToScan = ['us-east-1'];
        }
    }

    const isMultiRegion = regionsToScan.length > 1;

    const results = {
        platform: 'AWS',
        accountId: 'Unknown',
        region: region,
        services: {
            'identity-access': { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'compute':         { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'storage':         { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'databases':       { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'network':         { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'serverless':      { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'operations':      { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'artifacts':       { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'loadbalancing':   { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'analytics':       { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            'aiml':            { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } }
        }
    };

    const cleanID = (id) => {
        if (!id) return '';
        return String(id).toLowerCase().trim();
    };

    const addVuln = (service, asset, description, severity, remediation, itemRegion) => {
        if (!results.services[service]) return;
        const suffix = (isMultiRegion && itemRegion) ? ` (${itemRegion})` : "";
        results.services[service].vulnerabilities.push({ asset: String(asset || '').toLowerCase().trim() + suffix, description, severity, remediation });
        if (severity === 'High' || severity === 'Critical') results.services[service].summary.high++;
        else if (severity === 'Medium') results.services[service].summary.medium++;
        else results.services[service].summary.low++;
    };

    const markSecure = (service, count = 1) => {
        if (results.services[service]) results.services[service].summary.secure += count;
    };

    const addInventory = (service, category, id, type, details, remarks = '-', itemRegion) => {
        if (!results.services[service]) return;
        const regionTag = (isMultiRegion && itemRegion) ? ` [${itemRegion}]` : "";
        results.services[service].inventory.push({ category, id: cleanID(id), type, details, remarks: remarks + regionTag, status: 'Active' });
    };

    let completedSections = 0;
    // Global: IAM, S3, Route53, GuardDuty-account-level = 4
    // Regional per region: EC2, RDS, VPC, Lambda, CloudTrail, ELB, ECS, ECR, EKS, CloudWatch, SNS, SQS, ElastiCache, DynamoDB, Redshift, KMS = 16
    const GLOBAL_SECTIONS = 4;
    const REGIONAL_SECTIONS_PER_REGION = 16;
    const totalSections = GLOBAL_SECTIONS + (REGIONAL_SECTIONS_PER_REGION * regionsToScan.length);

    const auditWrapper = async (name, fn) => {
        try {
            await fn();
        } catch (e) {
            logCallback(`⚠️ ${name}: ${e.message}`);
        } finally {
            completedSections++;
            const percent = Math.min(99, Math.round((completedSections / totalSections) * 95));
            logCallback(`PROGRESS: ${percent}%`);
        }
    };

    // Get Account ID
    try {
        const sts = new AWS.STS(baseConfig);
        const identity = await sts.getCallerIdentity().promise();
        results.accountId = identity.Account;
        logCallback(`✅ Connected to AWS Account: ${results.accountId}`);
    } catch (e) {
        logCallback(`CRITICAL: Cannot connect to AWS: ${e.message}`);
        throw e;
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // GLOBAL SERVICES
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // 1. IAM & Identity (Global)
    await auditWrapper("IAM Global", async () => {
        logCallback("🔍 Scanning IAM & Identity Access (Global)...");
        const iam = new AWS.IAM(baseConfig);

        try {
            const summary = await iam.getAccountSummary().promise();
            if (summary.SummaryMap.AccountMFAEnabled === 0)
                addVuln('identity-access', 'Root Account', 'Root user MFA is NOT enabled.', 'Critical', 'Enable hardware or virtual MFA on the root account immediately.');
            else markSecure('identity-access');
            if (summary.SummaryMap.AccountAccessKeysPresent > 0)
                addVuln('identity-access', 'Root Account', 'Root account has active access keys.', 'Critical', 'Delete root access keys; use IAM roles instead.');
            else markSecure('identity-access');
        } catch (e) {}

        try {
            const pwPolicy = await iam.getAccountPasswordPolicy().promise();
            const p = pwPolicy.PasswordPolicy;
            if (!p.RequireUppercaseCharacters || !p.RequireLowercaseCharacters || !p.RequireNumbers || !p.RequireSymbols)
                addVuln('identity-access', 'Password Policy', 'Password policy does not enforce complexity.', 'Medium', 'Enforce uppercase, lowercase, numbers and symbols.');
            else markSecure('identity-access');
            if ((p.MaxPasswordAge || 999) > 90)
                addVuln('identity-access', 'Password Policy', `Password max age is ${p.MaxPasswordAge || 'unlimited'} days (>90).`, 'Medium', 'Set max password age to 90 days or less.');
            else markSecure('identity-access');
            if (!p.PasswordReusePrevention || p.PasswordReusePrevention < 5)
                addVuln('identity-access', 'Password Policy', 'Password reuse not restricted (< 5 previous).', 'Low', 'Prevent reuse of the last 5+ passwords.');
            else markSecure('identity-access');
        } catch (e) {
            addVuln('identity-access', 'Password Policy', 'No IAM account password policy configured.', 'High', 'Configure a strong password policy.');
        }

        try {
            const adminPolicy = await iam.listEntitiesForPolicy({ PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }).promise();
            const adminCount = adminPolicy.PolicyGroups.length + adminPolicy.PolicyUsers.length + adminPolicy.PolicyRoles.length;
            if (adminCount > 3) addVuln('identity-access', 'IAM Policies', `${adminCount} entities have AdministratorAccess — overly permissive.`, 'High', 'Apply principle of least privilege.');
            else markSecure('identity-access');
        } catch (e) {}

        try {
            const usersResp = await iam.listUsers().promise();
            for (const user of usersResp.Users) {
                addInventory('identity-access', 'IAM', user.UserName, 'IAM User', `Last Login: ${user.PasswordLastUsed ? new Date(user.PasswordLastUsed).toLocaleDateString() : 'Never'}`, 'IAM User');
                try {
                    const keys = await iam.listAccessKeys({ UserName: user.UserName }).promise();
                    for (const key of keys.AccessKeyMetadata) {
                        const ageDays = Math.floor((new Date() - new Date(key.CreateDate)) / (1000 * 60 * 60 * 24));
                        if (ageDays > 90) addVuln('identity-access', user.UserName, `Access key ${key.AccessKeyId} is ${ageDays} days old.`, 'High', 'Rotate access keys every 90 days.');
                        else markSecure('identity-access');
                    }
                } catch (e) {}
                try {
                    const mfa = await iam.listMFADevices({ UserName: user.UserName }).promise();
                    if (mfa.MFADevices.length === 0) addVuln('identity-access', user.UserName, 'IAM user has no MFA device.', 'High', 'Enforce MFA for all IAM users.');
                    else markSecure('identity-access');
                } catch (e) {}
            }
        } catch (e) {}

        try {
            const roles = await iam.listRoles().promise();
            for (const role of roles.Roles) {
                const doc = decodeURIComponent(JSON.stringify(role.AssumeRolePolicyDocument));
                if (doc.includes('"AWS":"*"') || doc.includes('"Principal":"*"')) {
                    addVuln('identity-access', role.RoleName, 'Role trust policy allows assumption by ANY AWS principal.', 'Critical', 'Restrict trust policy to specific accounts/services.');
                } else markSecure('identity-access');
                addInventory('identity-access', 'IAM', role.RoleName, 'IAM Role', `Created: ${new Date(role.CreateDate).toLocaleDateString()}`, 'Role');
            }
        } catch (e) {}
    });

    // 2. S3 Storage (Global)
    await auditWrapper("S3 Global", async () => {
        logCallback("🔍 Scanning S3 Buckets (Global)...");
        const s3 = new AWS.S3(baseConfig);
        try {
            const bucketsResp = await s3.listBuckets().promise();
            logCallback(`   Found ${bucketsResp.Buckets.length} S3 buckets.`);
            for (const bucket of bucketsResp.Buckets) {
                let bucketRegion = 'us-east-1';
                try {
                    const loc = await s3.getBucketLocation({ Bucket: bucket.Name }).promise();
                    bucketRegion = loc.LocationConstraint || 'us-east-1';
                } catch (e) {}
                addInventory('storage', 'Storage', bucket.Name, 'S3 Bucket', `Region: ${bucketRegion}`, 'Object Storage');

                try {
                    const pab = await s3.getPublicAccessBlock({ Bucket: bucket.Name }).promise();
                    const c = pab.PublicAccessBlockConfiguration;
                    if (!c.BlockPublicAcls || !c.IgnorePublicAcls || !c.BlockPublicPolicy || !c.RestrictPublicBuckets)
                        addVuln('storage', bucket.Name, 'S3 Public Access Block is incomplete.', 'Critical', 'Enable all 4 "Block Public Access" settings.');
                    else markSecure('storage');
                } catch (e) {
                    addVuln('storage', bucket.Name, 'No Public Access Block configured — bucket may be public.', 'Critical', 'Enable Block Public Access.');
                }

                try {
                    await s3.getBucketEncryption({ Bucket: bucket.Name }).promise();
                    markSecure('storage');
                } catch (e) {
                    addVuln('storage', bucket.Name, 'Default encryption not enabled.', 'Medium', 'Enable AES-256 or SSE-KMS default encryption.');
                }

                try {
                    const versioning = await s3.getBucketVersioning({ Bucket: bucket.Name }).promise();
                    if (!versioning.Status || versioning.Status !== 'Enabled')
                        addVuln('storage', bucket.Name, 'S3 versioning is disabled — data loss risk.', 'Low', 'Enable versioning to protect against accidental deletion.');
                    else markSecure('storage');
                } catch (e) {}

                try {
                    const logging = await s3.getBucketLogging({ Bucket: bucket.Name }).promise();
                    if (!logging.LoggingEnabled)
                        addVuln('storage', bucket.Name, 'S3 access logging is disabled.', 'Low', 'Enable server access logging for audit visibility.');
                    else markSecure('storage');
                } catch (e) {}
            }
        } catch (e) {}
    });

    // 3. Route 53 (Global)
    await auditWrapper("Route53 Global", async () => {
        logCallback("🔍 Scanning Route 53 DNS (Global)...");
        const route53 = new AWS.Route53(baseConfig);
        try {
            const zones = await route53.listHostedZones().promise();
            for (const zone of zones.HostedZones) {
                addInventory('network', 'DNS', zone.Name, 'Route 53 Hosted Zone', `Type: ${zone.Config.PrivateZone ? 'Private' : 'Public'}`, 'DNS Zone');
                if (!zone.Config.PrivateZone) markSecure('network');
            }
            if (zones.HostedZones.length === 0) markSecure('network');
        } catch (e) {}
    });

    // 4. CloudFront (Global)
    await auditWrapper("CloudFront Global", async () => {
        logCallback("🔍 Scanning CloudFront Distributions (Global)...");
        const cf = new AWS.CloudFront(baseConfig);
        try {
            const dists = await cf.listDistributions().promise();
            const items = dists.DistributionList.Items || [];
            for (const dist of items) {
                addInventory('network', 'CDN', dist.DomainName, 'CloudFront Distribution', `Status: ${dist.Status}`, 'CDN');
                if (dist.ViewerCertificate && dist.ViewerCertificate.MinimumProtocolVersion) {
                    if (dist.ViewerCertificate.MinimumProtocolVersion === 'SSLv3' || dist.ViewerCertificate.MinimumProtocolVersion === 'TLSv1')
                        addVuln('network', dist.DomainName, `CloudFront uses outdated TLS: ${dist.ViewerCertificate.MinimumProtocolVersion}.`, 'High', 'Set minimum TLS version to TLSv1.2_2021.');
                    else markSecure('network');
                }
                if (dist.HttpVersion === 'http1.1')
                    addVuln('network', dist.DomainName, 'CloudFront not using HTTP/2 or HTTP/3.', 'Low', 'Enable HTTP/2 or HTTP/3 for improved security and performance.');
                else markSecure('network');
            }
        } catch (e) {}
    });

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // REGIONAL SERVICES (Parallel scan across all regions)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    logCallback(`🌐 Starting parallel scan across ${regionsToScan.length} regions: All Regions`);

    const scanRegion = async (r) => {
        const cfg = { 
            accessKeyId: accessKeyId, 
            secretAccessKey: secretAccessKey, 
            region: r 
        };

        // ── 1. EC2 & Compute ──────────────────────────────
        await auditWrapper(`EC2 [${r}]`, async () => {
            const ec2 = new AWS.EC2(cfg);
            try {
                // Security Groups
                const sgs = await ec2.describeSecurityGroups().promise();
                for (const sg of sgs.SecurityGroups) {
                    addInventory('compute', 'Networking', sg.GroupId, 'Security Group', sg.GroupName, 'Firewall', r);
                    for (const rule of sg.IpPermissions || []) {
                        const isPublicIPv4 = (rule.IpRanges || []).some(x => x.CidrIp === '0.0.0.0/0');
                        const isPublicIPv6 = (rule.Ipv6Ranges || []).some(x => x.CidrIpv6 === '::/0');
                        if (isPublicIPv4 || isPublicIPv6) {
                            if (rule.IpProtocol === '-1') addVuln('compute', sg.GroupId, 'ALL PORTS open to internet (0.0.0.0/0).', 'Critical', 'Restrict to specific CIDR ranges.', r);
                            else if (rule.FromPort === 22) addVuln('compute', sg.GroupId, 'SSH (22) open to internet.', 'High', 'Restrict SSH; use AWS Systems Manager Session Manager.', r);
                            else if (rule.FromPort === 3389) addVuln('compute', sg.GroupId, 'RDP (3389) open to internet.', 'High', 'Restrict RDP; use SSM Session Manager.', r);
                            else if (rule.FromPort === 3306) addVuln('compute', sg.GroupId, 'MySQL (3306) open to internet.', 'High', 'Restrict database ports to known IPs.', r);
                            else if (rule.FromPort === 5432) addVuln('compute', sg.GroupId, 'PostgreSQL (5432) open to internet.', 'High', 'Restrict database ports to known IPs.', r);
                            else addVuln('compute', sg.GroupId, `Port ${rule.FromPort} open to 0.0.0.0/0.`, 'Low', 'Verify if public exposure is required.', r);
                        }
                    }
                }

                // EC2 Instances
                const instancesResp = await ec2.describeInstances().promise();
                for (const res of instancesResp.Reservations) {
                    for (const inst of res.Instances) {
                        if (inst.State.Name === 'terminated') continue;
                        const name = (inst.Tags || []).find(t => t.Key === 'Name')?.Value || inst.InstanceId;
                        addInventory('compute', 'EC2', inst.InstanceId, `EC2 (${inst.InstanceType})`, `AZ: ${inst.Placement?.AvailabilityZone}`, inst.State.Name, r);
                        if (inst.PublicIpAddress) addVuln('compute', name, `Public IP ${inst.PublicIpAddress} assigned.`, 'Medium', 'Use private subnets + NAT. Use SSM for access.', r);
                        else markSecure('compute');
                        if (!inst.MetadataOptions || inst.MetadataOptions.HttpTokens !== 'required') addVuln('compute', name, 'IMDSv1 enabled — vulnerable to SSRF.', 'High', 'Set HttpTokens=required to enforce IMDSv2.', r);
                        else markSecure('compute');
                        if (!inst.IamInstanceProfile) addVuln('compute', name, 'No IAM instance profile attached.', 'Low', 'Attach an instance profile with minimal permissions.', r);
                        else markSecure('compute');
                    }
                }

                // EBS Volumes
                try {
                    const vols = await ec2.describeVolumes().promise();
                    for (const vol of vols.Volumes) {
                        addInventory('compute', 'Storage', vol.VolumeId, `EBS (${vol.VolumeType})`, `${vol.Size} GB`, vol.State, r);
                        if (!vol.Encrypted) addVuln('compute', vol.VolumeId, 'EBS volume is not encrypted.', 'Medium', 'Encrypt EBS volumes or create an encrypted snapshot.', r);
                        else markSecure('compute');
                    }
                } catch (e) {}

                // AMIs (custom)
                try {
                    const images = await ec2.describeImages({ Owners: ['self'] }).promise();
                    for (const img of images.Images) {
                        addInventory('compute', 'AMI', img.ImageId, 'Custom AMI', img.Name || img.ImageId, img.Public ? '⚠️ Public' : 'Private', r);
                        if (img.Public) addVuln('compute', img.ImageId, 'Custom AMI is publicly accessible.', 'High', 'Make AMI private unless intentionally public.', r);
                        else markSecure('compute');
                    }
                } catch (e) {}
            } catch (e) {}
        });

        // ── 2. RDS (Regional) ──────────────────────────────
        await auditWrapper(`RDS [${r}]`, async () => {
            const rds = new AWS.RDS(cfg);
            try {
                const dbs = await rds.describeDBInstances().promise();
                for (const db of dbs.DBInstances) {
                    addInventory('databases', 'RDS', db.DBInstanceIdentifier, `RDS (${db.Engine} ${db.EngineVersion})`, `Tier: ${db.DBInstanceClass}`, db.DBInstanceStatus, r);
                    if (!db.StorageEncrypted) addVuln('databases', db.DBInstanceIdentifier, 'RDS storage is not encrypted.', 'Critical', 'Enable storage encryption (requires instance recreation).', r);
                    else markSecure('databases');
                    if (db.PubliclyAccessible) addVuln('databases', db.DBInstanceIdentifier, 'RDS instance is publicly accessible.', 'Critical', 'Disable public accessibility and use private subnets.', r);
                    else markSecure('databases');
                    if (!db.BackupRetentionPeriod || db.BackupRetentionPeriod < 7) addVuln('databases', db.DBInstanceIdentifier, `Backup retention is ${db.BackupRetentionPeriod || 0} days (< 7).`, 'Medium', 'Set backup retention to 7+ days.', r);
                    else markSecure('databases');
                    if (!db.MultiAZ) addVuln('databases', db.DBInstanceIdentifier, 'Multi-AZ is disabled — single point of failure.', 'Low', 'Enable Multi-AZ for production workloads.', r);
                    else markSecure('databases');
                    if (!db.DeletionProtection) addVuln('databases', db.DBInstanceIdentifier, 'Deletion protection is disabled.', 'Low', 'Enable deletion protection to prevent accidental removal.', r);
                    else markSecure('databases');
                }
            } catch (e) {}
            try {
                const clusters = await rds.describeDBClusters().promise();
                for (const cluster of clusters.DBClusters) {
                    addInventory('databases', 'Aurora', cluster.DBClusterIdentifier, `Aurora (${cluster.Engine})`, `AZ: ${(cluster.AvailabilityZones || []).join(', ')}`, cluster.Status, r);
                    if (!cluster.StorageEncrypted) addVuln('databases', cluster.DBClusterIdentifier, 'Aurora cluster storage not encrypted.', 'Critical', 'Enable encryption at rest.', r);
                    else markSecure('databases');
                    if (!cluster.DeletionProtection) addVuln('databases', cluster.DBClusterIdentifier, 'Aurora cluster deletion protection disabled.', 'Low', 'Enable deletion protection.', r);
                    else markSecure('databases');
                }
            } catch (e) {}
        });

        // ── 3. VPC & Networking ────────────────────────────
        await auditWrapper(`VPC [${r}]`, async () => {
            const ec2 = new AWS.EC2(cfg);
            try {
                const vpcs = await ec2.describeVpcs().promise();
                for (const vpc of vpcs.Vpcs) {
                    const name = (vpc.Tags || []).find(t => t.Key === 'Name')?.Value || vpc.VpcId;
                    addInventory('network', 'VPC', vpc.VpcId, vpc.IsDefault ? 'Default VPC' : 'VPC', vpc.CidrBlock, vpc.State, r);
                    if (vpc.IsDefault) addVuln('network', vpc.VpcId, 'Default VPC exists — resources should use custom VPCs.', 'Low', 'Create a custom VPC and delete the default VPC.', r);
                    const logs = await ec2.describeFlowLogs({ Filter: [{ Name: 'resource-id', Values: [vpc.VpcId] }] }).promise();
                    if (logs.FlowLogs.length === 0) addVuln('network', name, 'VPC Flow Logs not enabled.', 'Medium', 'Enable VPC Flow Logs to S3 or CloudWatch.', r);
                    else markSecure('network');
                }

                // Network ACLs
                const nacls = await ec2.describeNetworkAcls().promise();
                for (const nacl of nacls.NetworkAcls) {
                    for (const entry of nacl.Entries || []) {
                        if (!entry.Egress && entry.RuleAction === 'allow' && entry.CidrBlock === '0.0.0.0/0' && entry.Protocol === '-1')
                            addVuln('network', nacl.NetworkAclId, 'NACL allows ALL inbound traffic from 0.0.0.0/0.', 'High', 'Restrict NACL inbound rules.', r);
                    }
                }
            } catch (e) {}
        });

        // ── 4. Lambda (Regional) ──────────────────────────
        await auditWrapper(`Lambda [${r}]`, async () => {
            const lambda = new AWS.Lambda(cfg);
            try {
                const fns = await lambda.listFunctions().promise();
                for (const f of fns.Functions) {
                    addInventory('serverless', 'Lambda', f.FunctionName, `Lambda (${f.Runtime})`, `Memory: ${f.MemorySize}MB`, 'Active', r);
                    const deprecated = ['nodejs6.10', 'nodejs8.10', 'nodejs10.x', 'nodejs12.x', 'nodejs14.x', 'python2.7', 'python3.6', 'java8', 'ruby2.5', 'dotnetcore2.1', 'dotnetcore3.1'];
                    if (deprecated.some(d => (f.Runtime || '').startsWith(d.replace('.x','')))) addVuln('serverless', f.FunctionName, `Deprecated runtime: ${f.Runtime}.`, 'High', 'Update to a supported runtime version.', r);
                    else markSecure('serverless');
                    if (!f.VpcConfig || !f.VpcConfig.VpcId) addVuln('serverless', f.FunctionName, 'Lambda not deployed in a VPC.', 'Low', 'Deploy Lambda in a VPC for network isolation.', r);
                    else markSecure('serverless');
                    try {
                        const policy = await lambda.getPolicy({ FunctionName: f.FunctionName }).promise();
                        const pDoc = JSON.parse(policy.Policy);
                        for (const stmt of pDoc.Statement || []) {
                            if (stmt.Principal === '*' || stmt.Principal?.AWS === '*') addVuln('serverless', f.FunctionName, 'Lambda has public invocation policy (Principal: *).', 'Critical', 'Restrict Lambda resource policy to known callers.', r);
                        }
                    } catch (e) { markSecure('serverless'); }
                }
            } catch (e) {}
        });

        // ── 5. CloudTrail (Regional) ──────────────────────
        await auditWrapper(`CloudTrail [${r}]`, async () => {
            const ct = new AWS.CloudTrail(cfg);
            try {
                const trails = await ct.describeTrails({ includeShadowTrails: false }).promise();
                if (trails.trailList.length === 0) {
                    addVuln('operations', 'CloudTrail', `No CloudTrail configured in ${r}.`, 'High', 'Enable CloudTrail to log API activity.', r);
                } else {
                    for (const trail of trails.trailList) {
                        addInventory('operations', 'Audit', trail.TrailARN, 'CloudTrail', `Bucket: ${trail.S3BucketName}`, 'Active', r);
                        try {
                            const status = await ct.getTrailStatus({ Name: trail.TrailARN }).promise();
                            if (!status.IsLogging) addVuln('operations', trail.Name, 'CloudTrail logging is disabled.', 'High', 'Enable logging on the trail.', r);
                            else markSecure('operations');
                        } catch (e) {}
                        if (!trail.LogFileValidationEnabled) addVuln('operations', trail.Name, 'Log file validation disabled.', 'Medium', 'Enable log file validation to detect tampering.', r);
                        else markSecure('operations');
                        if (!trail.KMSKeyId) addVuln('operations', trail.Name, 'CloudTrail logs not encrypted with KMS.', 'Low', 'Configure SSE-KMS encryption for CloudTrail.', r);
                        else markSecure('operations');
                    }
                }
            } catch (e) {}
        });

        // ── 6. ELB / ALB / NLB (Regional) ────────────────
        await auditWrapper(`ELB [${r}]`, async () => {
            const elbv2 = new AWS.ELBv2(cfg);
            try {
                const lbs = await elbv2.describeLoadBalancers().promise();
                for (const lb of lbs.LoadBalancers) {
                    addInventory('loadbalancing', 'ELB', lb.LoadBalancerName, `${lb.Type?.toUpperCase()} Load Balancer`, `Scheme: ${lb.Scheme}`, lb.State?.Code, r);
                    if (lb.Scheme === 'internet-facing') {
                        markSecure('loadbalancing');
                        // Check deletion protection
                        try {
                            const attrs = await elbv2.describeLoadBalancerAttributes({ LoadBalancerArn: lb.LoadBalancerArn }).promise();
                            const delProtect = attrs.Attributes.find(a => a.Key === 'deletion_protection.enabled');
                            if (!delProtect || delProtect.Value !== 'true') addVuln('loadbalancing', lb.LoadBalancerName, 'ELB deletion protection is disabled.', 'Low', 'Enable deletion protection.', r);
                            else markSecure('loadbalancing');
                            const logging = attrs.Attributes.find(a => a.Key === 'access_logs.s3.enabled');
                            if (!logging || logging.Value !== 'true') addVuln('loadbalancing', lb.LoadBalancerName, 'ELB access logging not enabled.', 'Low', 'Enable access logs to S3 for monitoring.', r);
                            else markSecure('loadbalancing');
                        } catch (e) {}
                    }
                    // Check listeners for HTTPS
                    try {
                        const listeners = await elbv2.describeListeners({ LoadBalancerArn: lb.LoadBalancerArn }).promise();
                        const hasHTTPS = listeners.Listeners.some(l => l.Protocol === 'HTTPS' || l.Protocol === 'TLS');
                        const hasHTTP  = listeners.Listeners.some(l => l.Protocol === 'HTTP');
                        if (hasHTTP && !hasHTTPS) addVuln('loadbalancing', lb.LoadBalancerName, 'ELB has HTTP listener but no HTTPS.', 'High', 'Add HTTPS listener and redirect HTTP to HTTPS.', r);
                        else if (hasHTTPS) markSecure('loadbalancing');
                    } catch (e) {}
                }
            } catch (e) {}
            // Classic ELBs
            try {
                const elb = new AWS.ELB(cfg);
                const classicLBs = await elb.describeLoadBalancers().promise();
                for (const lb of classicLBs.LoadBalancerDescriptions) {
                    addInventory('loadbalancing', 'ELB', lb.LoadBalancerName, 'Classic ELB', `Scheme: ${lb.Scheme}`, 'Active', r);
                    addVuln('loadbalancing', lb.LoadBalancerName, 'Classic ELB (deprecated). Use ALB/NLB instead.', 'Low', 'Migrate to Application or Network Load Balancer.', r);
                }
            } catch (e) {}
        });

        // ── 7. ECS (Regional) ────────────────────────────
        await auditWrapper(`ECS [${r}]`, async () => {
            const ecs = new AWS.ECS(cfg);
            try {
                const clusters = await ecs.listClusters().promise();
                for (const arn of clusters.clusterArns) {
                    const detail = await ecs.describeClusters({ clusters: [arn] }).promise();
                    for (const cluster of detail.clusters) {
                        addInventory('compute', 'ECS', cluster.clusterName, 'ECS Cluster', `Tasks: ${cluster.runningTasksCount}`, cluster.status, r);
                        if (cluster.settings) {
                            const containerInsights = cluster.settings.find(s => s.name === 'containerInsights');
                            if (!containerInsights || containerInsights.value !== 'enabled') addVuln('compute', cluster.clusterName, 'ECS Container Insights not enabled.', 'Low', 'Enable Container Insights for observability.', r);
                            else markSecure('compute');
                        }
                    }
                }
            } catch (e) {}
        });

        // ── 8. ECR (Regional) ────────────────────────────
        await auditWrapper(`ECR [${r}]`, async () => {
            const ecr = new AWS.ECR(cfg);
            try {
                const repos = await ecr.describeRepositories().promise();
                for (const repo of repos.repositories) {
                    addInventory('artifacts', 'ECR', repo.repositoryName, 'ECR Repository', `URI: ${repo.repositoryUri}`, 'Active', r);
                    if (!repo.imageScanningConfiguration?.scanOnPush) addVuln('artifacts', repo.repositoryName, 'ECR scan on push is disabled.', 'Medium', 'Enable scan on push to detect vulnerabilities.', r);
                    else markSecure('artifacts');
                    if (repo.encryptionConfiguration?.encryptionType !== 'KMS') addVuln('artifacts', repo.repositoryName, 'ECR repo not encrypted with KMS.', 'Low', 'Use KMS encryption for ECR repositories.', r);
                    else markSecure('artifacts');
                }
            } catch (e) {}
        });

        // ── 9. EKS (Regional) ────────────────────────────
        await auditWrapper(`EKS [${r}]`, async () => {
            const eks = new AWS.EKS(cfg);
            try {
                const clusters = await eks.listClusters().promise();
                for (const name of clusters.clusters) {
                    const detail = await eks.describeCluster({ name }).promise();
                    const cluster = detail.cluster;
                    addInventory('compute', 'EKS', cluster.name, `EKS (${cluster.version})`, `Endpoint: ${cluster.resourcesVpcConfig?.endpointPublicAccess ? 'Public' : 'Private'}`, cluster.status, r);
                    if (cluster.resourcesVpcConfig?.endpointPublicAccess) addVuln('compute', cluster.name, 'EKS API endpoint is publicly accessible.', 'High', 'Disable public endpoint or restrict to known CIDR ranges.', r);
                    else markSecure('compute');
                    if (!cluster.encryptionConfig || cluster.encryptionConfig.length === 0) addVuln('compute', cluster.name, 'EKS secrets are not encrypted with KMS.', 'Medium', 'Configure envelope encryption for secrets.', r);
                    else markSecure('compute');
                    if (cluster.logging?.clusterLogging?.[0]?.enabled !== true) addVuln('compute', cluster.name, 'EKS control plane logging not fully enabled.', 'Low', 'Enable all log types in EKS cluster logging.', r);
                    else markSecure('compute');
                }
            } catch (e) {}
        });

        // ── 10. CloudWatch (Regional) ────────────────────
        await auditWrapper(`CloudWatch [${r}]`, async () => {
            const cw = new AWS.CloudWatch(cfg);
            const cwLogs = new AWS.CloudWatchLogs(cfg);
            try {
                const alarms = await cw.describeAlarms().promise();
                if (alarms.MetricAlarms.length === 0) addVuln('operations', 'CloudWatch', `No CloudWatch alarms configured in ${r}.`, 'Medium', 'Set up alarms for critical metrics.', r);
                else {
                    const okAlarms = alarms.MetricAlarms.filter(a => a.StateValue === 'OK').length;
                    addInventory('operations', 'Monitoring', `alarms-${r}`, 'CloudWatch Alarms', `Total: ${alarms.MetricAlarms.length}, OK: ${okAlarms}`, 'Active', r);
                    markSecure('operations');
                }
            } catch (e) {}
            try {
                const groups = await cwLogs.describeLogGroups().promise();
                for (const group of groups.logGroups) {
                    if (!group.retentionInDays) addVuln('operations', group.logGroupName, 'CloudWatch Log Group has no retention policy.', 'Low', 'Set a retention policy (e.g., 90 days) to control costs.', r);
                    else markSecure('operations');
                    addInventory('operations', 'Logging', group.logGroupName, 'Log Group', `Retention: ${group.retentionInDays || 'Never expire'} days`, 'Active', r);
                }
            } catch (e) {}
        });

        // ── 11. SNS & SQS (Regional) ─────────────────────
        await auditWrapper(`SNS/SQS [${r}]`, async () => {
            const sns = new AWS.SNS(cfg);
            const sqs = new AWS.SQS(cfg);
            try {
                const topics = await sns.listTopics().promise();
                for (const topic of topics.Topics) {
                    const topicName = topic.TopicArn.split(':').pop();
                    addInventory('analytics', 'Messaging', topicName, 'SNS Topic', topic.TopicArn, 'Active', r);
                    try {
                        const attrs = await sns.getTopicAttributes({ TopicArn: topic.TopicArn }).promise();
                        if (!attrs.Attributes.KMSMasterKeyId) addVuln('analytics', topicName, 'SNS topic not encrypted with KMS.', 'Low', 'Enable SSE-KMS for SNS topic.', r);
                        else markSecure('analytics');
                    } catch (e) {}
                }
            } catch (e) {}
            try {
                const queues = await sqs.listQueues().promise();
                for (const url of queues.QueueUrls || []) {
                    const qName = url.split('/').pop();
                    addInventory('analytics', 'Messaging', qName, 'SQS Queue', url, 'Active', r);
                    try {
                        const attrs = await sqs.getQueueAttributes({ QueueUrl: url, AttributeNames: ['All'] }).promise();
                        if (!attrs.Attributes.SqsManagedSseEnabled && !attrs.Attributes.KmsMasterKeyId) addVuln('analytics', qName, 'SQS queue not encrypted.', 'Low', 'Enable SSE or KMS encryption.', r);
                        else markSecure('analytics');
                        if (!attrs.Attributes.RedrivePolicy) addVuln('analytics', qName, 'SQS queue has no Dead Letter Queue (DLQ).', 'Low', 'Configure a DLQ to handle failed messages.', r);
                        else markSecure('analytics');
                    } catch (e) {}
                }
            } catch (e) {}
        });

        // ── 12. ElastiCache (Regional) ───────────────────
        await auditWrapper(`ElastiCache [${r}]`, async () => {
            const ec = new AWS.ElastiCache(cfg);
            try {
                const clusters = await ec.describeCacheClusters().promise();
                for (const cluster of clusters.CacheClusters) {
                    addInventory('databases', 'Cache', cluster.CacheClusterId, `ElastiCache (${cluster.Engine} ${cluster.EngineVersion})`, `Node: ${cluster.CacheNodeType}`, cluster.CacheClusterStatus, r);
                    if (!cluster.AtRestEncryptionEnabled) addVuln('databases', cluster.CacheClusterId, 'ElastiCache not encrypted at rest.', 'Medium', 'Enable at-rest encryption.', r);
                    else markSecure('databases');
                    if (!cluster.TransitEncryptionEnabled) addVuln('databases', cluster.CacheClusterId, 'ElastiCache transit encryption not enabled.', 'Medium', 'Enable in-transit encryption (TLS).', r);
                    else markSecure('databases');
                }
            } catch (e) {}
        });

        // ── 13. DynamoDB (Regional) ──────────────────────
        await auditWrapper(`DynamoDB [${r}]`, async () => {
            const dynamo = new AWS.DynamoDB(cfg);
            try {
                const tables = await dynamo.listTables().promise();
                for (const tableName of tables.TableNames) {
                    try {
                        const table = await dynamo.describeTable({ TableName: tableName }).promise();
                        const t = table.Table;
                        addInventory('databases', 'DynamoDB', t.TableName, 'DynamoDB Table', `Items: ${t.ItemCount || 0}`, t.TableStatus, r);
                        if (!t.SSEDescription || t.SSEDescription.Status !== 'ENABLED') addVuln('databases', t.TableName, 'DynamoDB table not encrypted with KMS (CMK).', 'Low', 'Enable DynamoDB customer-managed KMS encryption.', r);
                        else markSecure('databases');
                        if (!t.PointInTimeRecoveryDescription || t.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus !== 'ENABLED') addVuln('databases', t.TableName, 'DynamoDB Point-in-Time Recovery (PITR) not enabled.', 'Medium', 'Enable PITR for data protection.', r);
                        else markSecure('databases');
                    } catch (e) {}
                }
            } catch (e) {}
        });

        // ── 14. Redshift (Regional) ──────────────────────
        await auditWrapper(`Redshift [${r}]`, async () => {
            const rs = new AWS.Redshift(cfg);
            try {
                const clusters = await rs.describeClusters().promise();
                for (const cluster of clusters.Clusters) {
                    addInventory('databases', 'Redshift', cluster.ClusterIdentifier, `Redshift (${cluster.NodeType})`, `Nodes: ${cluster.NumberOfNodes}`, cluster.ClusterStatus, r);
                    if (!cluster.Encrypted) addVuln('databases', cluster.ClusterIdentifier, 'Redshift cluster is not encrypted.', 'Critical', 'Enable encryption at rest.', r);
                    else markSecure('databases');
                    if (cluster.PubliclyAccessible) addVuln('databases', cluster.ClusterIdentifier, 'Redshift cluster publicly accessible.', 'Critical', 'Disable public access.', r);
                    else markSecure('databases');
                    if (!cluster.EnhancedVpcRouting) addVuln('databases', cluster.ClusterIdentifier, 'Enhanced VPC Routing disabled.', 'Low', 'Enable Enhanced VPC Routing for predictable network paths.', r);
                    else markSecure('databases');
                }
            } catch (e) {}
        });

        // ── 15. KMS (Regional) ──────────────────────────
        await auditWrapper(`KMS [${r}]`, async () => {
            const kms = new AWS.KMS(cfg);
            try {
                const keys = await kms.listKeys().promise();
                for (const key of keys.Keys) {
                    try {
                        const detail = await kms.describeKey({ KeyId: key.KeyId }).promise();
                        const km = detail.KeyMetadata;
                        if (km.KeyState === 'Disabled') addVuln('operations', km.KeyId, `KMS key "${km.Description || km.KeyId}" is disabled.`, 'Low', 'Review and delete or re-enable the key.', r);
                        else {
                            addInventory('operations', 'KMS', km.KeyId, `KMS Key (${km.KeyUsage})`, km.Description || 'No description', km.KeyState, r);
                            markSecure('operations');
                        }
                        if (km.KeyManager === 'CUSTOMER' && km.KeyRotationEnabled === false) addVuln('operations', km.Description || km.KeyId, 'KMS customer-managed key rotation not enabled.', 'Medium', 'Enable automatic annual key rotation.', r);
                        else if (km.KeyManager === 'CUSTOMER') markSecure('operations');
                    } catch (e) {}
                }
            } catch (e) {}
        });

        // ── 16. GuardDuty (Regional) ─────────────────────
        await auditWrapper(`GuardDuty [${r}]`, async () => {
            const gd = new AWS.GuardDuty(cfg);
            try {
                const detectors = await gd.listDetectors().promise();
                if (detectors.DetectorIds.length === 0) {
                    addVuln('aiml', 'GuardDuty', `GuardDuty not enabled in ${r}.`, 'High', 'Enable GuardDuty for intelligent threat detection.', r);
                } else {
                    for (const id of detectors.DetectorIds) {
                        const det = await gd.getDetector({ DetectorId: id }).promise();
                        addInventory('aiml', 'Security', id, 'GuardDuty Detector', `Updated: ${det.UpdatedAt}`, det.Status, r);
                        if (det.Status !== 'ENABLED') addVuln('aiml', 'GuardDuty', `GuardDuty detector not enabled in ${r}.`, 'High', 'Enable GuardDuty detector.', r);
                        else markSecure('aiml');
                        try {
                            const findings = await gd.listFindings({ DetectorId: id, FindingCriteria: { Criterion: { severity: { Gte: 7 } } } }).promise();
                            if (findings.FindingIds.length > 0) addVuln('aiml', 'GuardDuty', `${findings.FindingIds.length} HIGH-severity GuardDuty finding(s) in ${r}.`, 'High', 'Review and remediate GuardDuty findings.', r);
                            else markSecure('aiml');
                        } catch (e) {}
                    }
                }
            } catch (e) {}
        });
    };

    // Run all regional scans in PARALLEL
    await Promise.all(regionsToScan.map(r => scanRegion(r)));

    logCallback("PROGRESS: 100%");
    logCallback(`✅ AWS Full Security Audit Complete! Scanned ${regionsToScan.length} region(s) across all services.`);
    return results;
}

module.exports = { runAWSAudit };
