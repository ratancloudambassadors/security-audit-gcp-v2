const AWS = require('aws-sdk');

async function runAWSAudit(accessKeyId, secretAccessKey, region = 'us-east-1', logCallback) {
    AWS.config.update({
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
        region: region
    });

    logCallback("Authenticating with AWS...");
    
    const results = {
        platform: 'AWS',
        accountId: 'Unknown',
        region: region,
        services: {
            iam: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            ec2: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            s3: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            rds: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            vpc: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            cloudtrail: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            lambda: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            kms: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            devops: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            artifacts: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } }
        }
    };

    const cleanID = (id) => {
        if (!id) return '';
        // Remove prefixes like 'user/', 'group/', 'role/' and common ARN components if simple ID is needed
        // but for AWS we often want the full name or ARN. Let's lowercase for matching consistency.
        return id.toLowerCase().trim();
    };

    const addVuln = (service, asset, description, severity, remediation) => {
        const cleanedAsset = cleanID(asset);
        results.services[service].vulnerabilities.push({ asset: cleanedAsset, description, severity, remediation });
        if (severity === 'High' || severity === 'Critical') results.services[service].summary.high++;
        else if (severity === 'Medium') results.services[service].summary.medium++;
        else results.services[service].summary.low++;
    };

    const markSecure = (service, count = 1) => {
        results.services[service].summary.secure += count;
    };

    const addInventory = (service, category, id, type, details, remarks = '-') => {
        const cleanedId = cleanID(id);
        results.services[service].inventory.push({ category, id: cleanedId, type, details, remarks, status: 'Active' });
    };

    let completedSections = 0;
    const totalSections = 10; // Increased due to new modules

    const auditWrapper = async (name, fn) => {
        try {
            logCallback(`Scanning AWS ${name}...`);
            await fn();
            completedSections++;
            const percent = Math.min(100, Math.round((completedSections / totalSections) * 100));
            logCallback(`PROGRESS: ${percent}%`);
        } catch (e) {
            logCallback(`Error scanning ${name}: ${e.message}`);
        }
    };

    // Get Account ID
    try {
        const sts = new AWS.STS();
        const identity = await sts.getCallerIdentity().promise();
        results.accountId = identity.Account;
        logCallback(`Connected to AWS Account: ${results.accountId}`);
    } catch (e) {
        logCallback(`Failed to get AWS account ID: ${e.message}`);
    }

    // --- 1. IAM & Identity (12 checks) ---
    await auditWrapper("IAM & Identity", async () => {
        const iam = new AWS.IAM();

        // Root Account MFA
        try {
            const summary = await iam.getAccountSummary().promise();
            if (summary.SummaryMap.AccountMFAEnabled === 0) {
                addVuln('iam', 'Root Account', 'Root account MFA not enabled.', 'Critical', 'Enable MFA on root account immediately.');
            } else {
                markSecure('iam');
            }
        } catch (e) {}

        // Password Policy
        try {
            const policy = await iam.getAccountPasswordPolicy().promise();
            if (!policy.PasswordPolicy.RequireUppercaseCharacters || !policy.PasswordPolicy.RequireLowercaseCharacters ||
                !policy.PasswordPolicy.RequireNumbers || !policy.PasswordPolicy.RequireSymbols) {
                addVuln('iam', 'Password Policy', 'Weak password policy configured.', 'High', 'Enforce strong password requirements.');
            } else {
                markSecure('iam');
            }
        } catch (e) {
            addVuln('iam', 'Password Policy', 'No password policy configured.', 'High', 'Create a strong password policy.');
        }

        // Access Keys Rotation
        try {
            const users = await iam.listUsers().promise();
            for (const user of users.Users) {
                const keys = await iam.listAccessKeys({ UserName: user.UserName }).promise();
                for (const key of keys.AccessKeyMetadata) {
                    const ageDays = (new Date() - new Date(key.CreateDate)) / (1000 * 60 * 60 * 24);
                    if (ageDays > 90) {
                        addVuln('iam', user.UserName, `Access key ${key.AccessKeyId} is ${Math.floor(ageDays)} days old.`, 'High', 'Rotate access keys every 90 days.');
                    } else {
                        markSecure('iam');
                    }
                }
                addInventory('iam', 'IAM', user.UserName, 'IAM User', `Created: ${user.CreateDate}`, 'User identity');
            }
        } catch (e) {}

        // Unused IAM Users
        try {
            const credReport = await iam.generateCredentialReport().promise();
            // Wait for report generation
            await new Promise(resolve => setTimeout(resolve, 2000));
            const report = await iam.getCredentialReport().promise();
            const lines = Buffer.from(report.Content, 'base64').toString('utf-8').split('\n');
            lines.slice(1).forEach(line => {
                const fields = line.split(',');
                if (fields.length > 10) {
                    const username = fields[0];
                    const passwordLastUsed = fields[4];
                    const key1LastUsed = fields[10];
                    const key2LastUsed = fields[15];
                    
                    if (passwordLastUsed === 'N/A' && key1LastUsed === 'N/A' && key2LastUsed === 'N/A') {
                        addVuln('iam', username, 'IAM user has never been used.', 'Medium', 'Remove unused IAM users.');
                    }
                }
            });
        } catch (e) {}

        // IAM Policies with Wildcards
        try {
            const policies = await iam.listPolicies({ Scope: 'Local' }).promise();
            for (const policy of policies.Policies) {
                const policyVersion = await iam.getPolicyVersion({
                    PolicyArn: policy.Arn,
                    VersionId: policy.DefaultVersionId
                }).promise();
                const doc = JSON.parse(decodeURIComponent(policyVersion.PolicyVersion.Document));
                const hasWildcard = JSON.stringify(doc).includes('"*"');
                if (hasWildcard) {
                    addVuln('iam', policy.PolicyName, 'IAM policy contains wildcard (*) permissions.', 'High', 'Use least privilege principle with specific permissions.');
                } else {
                    markSecure('iam');
                }
            }
        } catch (e) {}

        // MFA on All Human Users (Improved)
        try {
            const users = await iam.listUsers().promise();
            for (const user of users.Users) {
                const mfaDevices = await iam.listMFADevices({ UserName: user.UserName }).promise();
                const hasMFA = mfaDevices.MFADevices.length > 0;
                
                // Detailed check for Admin roles
                const attachedPolicies = await iam.listAttachedUserPolicies({ UserName: user.UserName }).promise();
                const isPrivileged = attachedPolicies.AttachedPolicies.some(p => 
                    p.PolicyName.includes('Admin') || p.PolicyArn.includes('AdministratorAccess')
                );

                if (!hasMFA) {
                    const severity = isPrivileged ? 'Critical' : 'Medium';
                    addVuln('iam', user.UserName, `${isPrivileged ? 'Privileged user' : 'User'} has no MFA enabled.`, severity, 'Enable virtual or hardware MFA for this user.');
                } else {
                    markSecure('iam');
                }

                if (isPrivileged) {
                    addInventory('iam', 'Identity', user.UserName, 'IAM User', 'Privileged Account (Administrator)', 'MFA ' + (hasMFA ? 'Active' : 'Missing'));
                }
            }
        } catch (e) {}

        // Unused Access Keys (Expanded)
        try {
            const users = await iam.listUsers().promise();
            for (const user of users.Users) {
                const keys = await iam.listAccessKeys({ UserName: user.UserName }).promise();
                for (const key of keys.AccessKeyMetadata) {
                    if (key.Status === 'Active') {
                        const lastUsed = await iam.getAccessKeyLastUsed({ AccessKeyId: key.AccessKeyId }).promise();
                        const usedDate = lastUsed.AccessKeyLastUsed.LastUsedDate;
                        
                        if (usedDate) {
                            const inactiveDays = (new Date() - new Date(usedDate)) / (1000 * 60 * 60 * 24);
                            if (inactiveDays > 90) {
                                addVuln('iam', user.UserName, `Access key ${key.AccessKeyId} has not been used for ${Math.floor(inactiveDays)} days.`, 'High', 'Deactivate or delete unused access keys.');
                            } else {
                                markSecure('iam');
                            }
                        }
                    }
                }
            }
        } catch (e) {}

        // IAM Policies with Wildcards (Improved)
        try {
            const policies = await iam.listPolicies({ Scope: 'Local' }).promise();
            for (const policy of policies.Policies) {
                const policyVersion = await iam.getPolicyVersion({
                    PolicyArn: policy.Arn,
                    VersionId: policy.DefaultVersionId
                }).promise();
                const doc = JSON.parse(decodeURIComponent(policyVersion.PolicyVersion.Document));
                const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
                
                const hasFullAccess = statements.some(s => s.Effect === 'Allow' && s.Action === '*' && s.Resource === '*');
                if (hasFullAccess) {
                    addVuln('iam', policy.PolicyName, 'IAM policy grants full Administrator access via wildcards.', 'Critical', 'Replace wildcard policies with granular permissions.');
                } else if (JSON.stringify(doc).includes('"*"')) {
                    addVuln('iam', policy.PolicyName, 'IAM policy contains wildcard (*) permissions.', 'High', 'Use specific resource ARNs and actions.');
                } else {
                    markSecure('iam');
                }
            }
        } catch (e) {}
    });

    // --- 2. EC2 & Compute (10 checks) ---
    await auditWrapper("EC2 & Compute", async () => {
        const ec2 = new AWS.EC2({ region: region });

        // Security Groups - SSH/RDP from 0.0.0.0/0
        try {
            const sgs = await ec2.describeSecurityGroups().promise();
            sgs.SecurityGroups.forEach(sg => {
                addInventory('ec2', 'Networking', sg.GroupId, 'Security Group', sg.GroupName, 'Firewall rules');
                sg.IpPermissions.forEach(rule => {
                    const hasPublicAccess = rule.IpRanges && rule.IpRanges.some(r => r.CidrIp === '0.0.0.0/0');
                    if (hasPublicAccess && (rule.FromPort === 22 || rule.FromPort === 3389)) {
                        const port = rule.FromPort === 22 ? 'SSH' : 'RDP';
                        addVuln('ec2', sg.GroupId, `${port} (port ${rule.FromPort}) open to 0.0.0.0/0.`, 'Critical', 'Restrict access to specific IP ranges.');
                    }
                });
            });
        } catch (e) {}

        // EC2 Instances
        try {
            const instances = await ec2.describeInstances().promise();
            instances.Reservations.forEach(reservation => {
                reservation.Instances.forEach(instance => {
                    addInventory('ec2', 'Compute', instance.InstanceId, 'EC2 Instance', `Type: ${instance.InstanceType}`, instance.State.Name);
                    
                    // IMDSv2 Check
                    if (!instance.MetadataOptions || instance.MetadataOptions.HttpTokens !== 'required') {
                        addVuln('ec2', instance.InstanceId, 'Instance not enforcing IMDSv2.', 'High', 'Require IMDSv2 for metadata access.');
                    } else {
                        markSecure('ec2');
                    }

                    // Public IP Check
                    if (instance.PublicIpAddress) {
                        addVuln('ec2', instance.InstanceId, 'Instance has public IP address.', 'Medium', 'Use private IPs and NAT gateway.');
                    } else {
                        markSecure('ec2');
                    }

                    // EBS Encryption
                    if (instance.BlockDeviceMappings) {
                        instance.BlockDeviceMappings.forEach(bdm => {
                            if (bdm.Ebs && !bdm.Ebs.Encrypted) {
                                addVuln('ec2', instance.InstanceId, `EBS volume ${bdm.Ebs.VolumeId} not encrypted.`, 'High', 'Enable EBS encryption.');
                            } else if (bdm.Ebs) {
                                markSecure('ec2');
                            }
                        });
                    }
                });
            });
        } catch (e) {}

        // Unused Elastic IPs
        try {
            const eips = await ec2.describeAddresses().promise();
            eips.Addresses.forEach(eip => {
                if (!eip.InstanceId && !eip.NetworkInterfaceId) {
                    addVuln('ec2', eip.PublicIp, 'Elastic IP not associated with any resource.', 'Low', 'Release unused Elastic IPs to save costs.');
                } else {
                    markSecure('ec2');
                }
            });
        } catch (e) {}

        // Public AMIs
        try {
            const amis = await ec2.describeImages({ Owners: ['self'] }).promise();
            amis.Images.forEach(ami => {
                if (ami.Public) {
                    addVuln('ec2', ami.ImageId, 'Custom AMI is publicly accessible.', 'High', 'Make the AMI private or restrict and share with specific accounts.');
                } else {
                    markSecure('ec2');
                }
            });
        } catch (e) {}

        // Unencrypted EBS Snapshots
        try {
            const snapshots = await ec2.describeSnapshots({ OwnerIds: ['self'] }).promise();
            snapshots.Snapshots.forEach(snap => {
                if (!snap.Encrypted) {
                    addVuln('ec2', snap.SnapshotId, 'EBS snapshot is not encrypted.', 'High', 'Enable encryption for all snapshots.');
                } else {
                    markSecure('ec2');
                }
            });
        } catch (e) {}
    });

    // --- 3. S3 Storage (10 checks) ---
    await auditWrapper("S3 Storage", async () => {
        const s3 = new AWS.S3();

        try {
            const buckets = await s3.listBuckets().promise();
            for (const bucket of buckets.Buckets) {
                addInventory('s3', 'Storage', bucket.Name, 'S3 Bucket', `Created: ${bucket.CreationDate}`, 'Object storage');

                // Public Access Block
                try {
                    const publicBlock = await s3.getPublicAccessBlock({ Bucket: bucket.Name }).promise();
                    if (!publicBlock.PublicAccessBlockConfiguration.BlockPublicAcls ||
                        !publicBlock.PublicAccessBlockConfiguration.BlockPublicPolicy) {
                        addVuln('s3', bucket.Name, 'Bucket public access not fully blocked.', 'Critical', 'Enable Block Public Access settings.');
                    } else {
                        markSecure('s3');
                    }
                } catch (e) {
                    addVuln('s3', bucket.Name, 'No public access block configuration.', 'Critical', 'Configure Block Public Access.');
                }

                // Bucket Encryption
                try {
                    await s3.getBucketEncryption({ Bucket: bucket.Name }).promise();
                    markSecure('s3');
                } catch (e) {
                    addVuln('s3', bucket.Name, 'Bucket encryption not enabled.', 'High', 'Enable default encryption (SSE-S3 or SSE-KMS).');
                }

                // Versioning
                try {
                    const versioning = await s3.getBucketVersioning({ Bucket: bucket.Name }).promise();
                    if (versioning.Status !== 'Enabled') {
                        addVuln('s3', bucket.Name, 'Bucket versioning not enabled.', 'Medium', 'Enable versioning for data protection.');
                    } else {
                        markSecure('s3');
                    }
                } catch (e) {}

                // Logging
                try {
                    const logging = await s3.getBucketLogging({ Bucket: bucket.Name }).promise();
                    if (!logging.LoggingEnabled) {
                        addVuln('s3', bucket.Name, 'Bucket access logging not enabled.', 'Medium', 'Enable access logging for audit trail.');
                    } else {
                        markSecure('s3');
                    }
                } catch (e) {}

                // MFA Delete
                try {
                    const versioning = await s3.getBucketVersioning({ Bucket: bucket.Name }).promise();
                    if (versioning.MFADelete !== 'Enabled') {
                        addVuln('s3', bucket.Name, 'MFA Delete not enabled.', 'Low', 'Enable MFA Delete for critical buckets.');
                    } else {
                        markSecure('s3');
                    }
                } catch (e) {}

                // S3 Public Policy Check (Improved)
                try {
                    const policy = await s3.getBucketPolicy({ Bucket: bucket.Name }).promise();
                    const policyDoc = JSON.parse(policy.Policy);
                    const statements = Array.isArray(policyDoc.Statement) ? policyDoc.Statement : [policyDoc.Statement];
                    const hasPublicStatement = statements.some(s => s.Effect === 'Allow' && (s.Principal === '*' || (s.Principal && s.Principal.AWS === '*')));
                    
                    if (hasPublicStatement) {
                        addVuln('s3', bucket.Name, 'Bucket policy allows public access.', 'Critical', 'Restrict bucket policy to specific VPCs or IAM users.');
                    } else {
                        markSecure('s3');
                    }
                } catch (e) {}

                // Public ACL Check
                try {
                    const acl = await s3.getBucketAcl({ Bucket: bucket.Name }).promise();
                    const isPublicACL = acl.Grants.some(g => 
                        g.Grantee.URI === 'http://acs.amazonaws.com/groups/global/AllUsers' ||
                        g.Grantee.URI === 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                    );
                    if (isPublicACL) {
                        addVuln('s3', bucket.Name, 'Bucket has public ACLs enabled.', 'Critical', 'Remove "Everyone" and "Any Authenticated User" permissions from ACLs.');
                    } else {
                        markSecure('s3');
                    }
                } catch (e) {}
            }
        } catch (e) {}
    });

    // --- 4. RDS & Databases (8 checks) ---
    await auditWrapper("RDS & Databases", async () => {
        const rds = new AWS.RDS({ region: region });

        try {
            const instances = await rds.describeDBInstances().promise();
            instances.DBInstances.forEach(db => {
                addInventory('rds', 'Databases', db.DBInstanceIdentifier, 'RDS Instance', `Engine: ${db.Engine}`, db.DBInstanceStatus);

                // Encryption at Rest
                if (!db.StorageEncrypted) {
                    addVuln('rds', db.DBInstanceIdentifier, 'Database not encrypted at rest.', 'Critical', 'Enable encryption at rest.');
                } else {
                    markSecure('rds');
                }

                // Public Accessibility
                if (db.PubliclyAccessible) {
                    addVuln('rds', db.DBInstanceIdentifier, 'Database is publicly accessible.', 'Critical', 'Disable public accessibility.');
                } else {
                    markSecure('rds');
                }

                // Automated Backups
                if (db.BackupRetentionPeriod === 0) {
                    addVuln('rds', db.DBInstanceIdentifier, 'Automated backups not enabled.', 'High', 'Enable automated backups with retention.');
                } else {
                    markSecure('rds');
                }

                // Multi-AZ
                if (!db.MultiAZ) {
                    addVuln('rds', db.DBInstanceIdentifier, 'Multi-AZ not enabled.', 'Medium', 'Enable Multi-AZ for high availability.');
                } else {
                    markSecure('rds');
                }

                // Minor Version Auto-Upgrade
                if (!db.AutoMinorVersionUpgrade) {
                    addVuln('rds', db.DBInstanceIdentifier, 'Auto minor version upgrade not enabled.', 'Low', 'Enable auto minor version upgrades.');
                } else {
                    markSecure('rds');
                }

                // Deletion Protection
                if (!db.DeletionProtection) {
                    addVuln('rds', db.DBInstanceIdentifier, 'Deletion protection not enabled.', 'Medium', 'Enable deletion protection for production databases.');
                } else {
                    markSecure('rds');
                }
            });
        } catch (e) {}
    });

    // --- 5. VPC & Networking (8 checks) ---
    await auditWrapper("VPC & Networking", async () => {
        const ec2 = new AWS.EC2({ region: region });

        // VPCs
        try {
            const vpcs = await ec2.describeVpcs().promise();
            vpcs.Vpcs.forEach(vpc => {
                addInventory('vpc', 'Networking', vpc.VpcId, 'VPC', `CIDR: ${vpc.CidrBlock}`, vpc.State);

                // Default VPC Check
                if (vpc.IsDefault) {
                    addVuln('vpc', vpc.VpcId, 'Using default VPC.', 'Medium', 'Create custom VPCs for production workloads.');
                } else {
                    markSecure('vpc');
                }
            });
        } catch (e) {}

        // VPC Flow Logs
        try {
            const vpcs = await ec2.describeVpcs().promise();
            const flowLogs = await ec2.describeFlowLogs().promise();
            vpcs.Vpcs.forEach(vpc => {
                const hasFlowLog = flowLogs.FlowLogs.some(fl => fl.ResourceId === vpc.VpcId);
                if (!hasFlowLog) {
                    addVuln('vpc', vpc.VpcId, 'VPC Flow Logs not enabled.', 'Medium', 'Enable VPC Flow Logs for network monitoring.');
                } else {
                    markSecure('vpc');
                }
            });
        } catch (e) {}

        // Network ACLs
        try {
            const nacls = await ec2.describeNetworkAcls().promise();
            nacls.NetworkAcls.forEach(nacl => {
                addInventory('vpc', 'Networking', nacl.NetworkAclId, 'Network ACL', `VPC: ${nacl.VpcId}`, 'Stateless firewall');
            });
        } catch (e) {}

        // Subnets - Auto-assign Public IP
        try {
            const subnets = await ec2.describeSubnets().promise();
            subnets.Subnets.forEach(subnet => {
                if (subnet.MapPublicIpOnLaunch) {
                    addVuln('vpc', subnet.SubnetId, 'Subnet auto-assigns public IPs.', 'Medium', 'Disable auto-assign public IP for private subnets.');
                } else {
                    markSecure('vpc');
                }
            });
        } catch (e) {}
    });

    // --- 6. CloudTrail & Logging (6 checks) ---
    await auditWrapper("CloudTrail & Logging", async () => {
        const cloudtrail = new AWS.CloudTrail({ region: region });
        const cloudwatch = new AWS.CloudWatchLogs({ region: region });
        const config = new AWS.ConfigService({ region: region });

        // CloudTrail Enabled
        try {
            const trails = await cloudtrail.describeTrails().promise();
            if (trails.trailList.length === 0) {
                addVuln('cloudtrail', 'CloudTrail', 'No CloudTrail trails configured.', 'Critical', 'Enable CloudTrail in all regions.');
            } else {
                trails.trailList.forEach(trail => {
                    addInventory('cloudtrail', 'Security', trail.Name, 'CloudTrail', `S3: ${trail.S3BucketName}`, 'Audit logging');

                    // Multi-region
                    if (!trail.IsMultiRegionTrail) {
                        addVuln('cloudtrail', trail.Name, 'Trail not enabled for all regions.', 'High', 'Enable multi-region trail.');
                    } else {
                        markSecure('cloudtrail');
                    }

                    // Log File Validation
                    if (!trail.LogFileValidationEnabled) {
                        addVuln('cloudtrail', trail.Name, 'Log file validation not enabled.', 'Medium', 'Enable log file validation.');
                    } else {
                        markSecure('cloudtrail');
                    }
                });
            }
        } catch (e) {}

        // Config Recorder
        try {
            const recorders = await config.describeConfigurationRecorders().promise();
            if (recorders.ConfigurationRecorders.length === 0) {
                addVuln('cloudtrail', 'AWS Config', 'Config Recorder not enabled.', 'High', 'Enable AWS Config for resource tracking.');
            } else {
                markSecure('cloudtrail');
            }
        } catch (e) {}

        // GuardDuty
        try {
            const guardduty = new AWS.GuardDuty({ region: region });
            const detectors = await guardduty.listDetectors().promise();
            if (detectors.DetectorIds.length === 0) {
                addVuln('cloudtrail', 'GuardDuty', 'GuardDuty not enabled.', 'High', 'Enable GuardDuty for threat detection.');
            } else {
                markSecure('cloudtrail');
            }
        } catch (e) {}
    });

    // --- 7. Lambda & Additional Services (6 checks) ---
    await auditWrapper("Lambda & Services", async () => {
        const lambda = new AWS.Lambda({ region: region });
        const kms = new AWS.KMS({ region: region });

        // Lambda Functions
        try {
            const functions = await lambda.listFunctions().promise();
            for (const func of functions.Functions) {
                addInventory('lambda', 'Serverless', func.FunctionName, 'Lambda Function', `Runtime: ${func.Runtime}`, 'Serverless function');

                // Public Access
                try {
                    const policy = await lambda.getPolicy({ FunctionName: func.FunctionName }).promise();
                    const policyDoc = JSON.parse(policy.Policy);
                    const hasPublicAccess = policyDoc.Statement.some(s => 
                        s.Principal === '*' || (s.Principal && s.Principal.AWS === '*')
                    );
                    if (hasPublicAccess) {
                        addVuln('lambda', func.FunctionName, 'Lambda function has public access.', 'Critical', 'Remove public access from Lambda function.');
                    } else {
                        markSecure('lambda');
                    }
                } catch (e) {
                    markSecure('lambda');
                }

                // VPC Configuration
                if (!func.VpcConfig || !func.VpcConfig.VpcId) {
                    addVuln('lambda', func.FunctionName, 'Lambda function not in VPC.', 'Low', 'Consider placing Lambda in VPC for private resource access.');
                }
            }
        } catch (e) {}

        // KMS Keys
        try {
            const keys = await kms.listKeys().promise();
            for (const key of keys.Keys) {
                const metadata = await kms.describeKey({ KeyId: key.KeyId }).promise();
                if (metadata.KeyMetadata.KeyState === 'Enabled') {
                    addInventory('kms', 'Security', key.KeyId, 'KMS Key', `Description: ${metadata.KeyMetadata.Description || 'N/A'}`, 'Encryption key');

                    // Key Rotation
                    try {
                        const rotation = await kms.getKeyRotationStatus({ KeyId: key.KeyId }).promise();
                        if (!rotation.KeyRotationEnabled) {
                            addVuln('kms', key.KeyId, 'KMS key rotation not enabled.', 'Medium', 'Enable automatic key rotation.');
                        } else {
                            markSecure('kms');
                        }
                    } catch (e) {}
                }
            }
        } catch (e) {}
    });

    // --- 8. DevOps (CodeBuild & CodePipeline) ---
    await auditWrapper("DevOps Services", async () => {
        const codebuild = new AWS.CodeBuild({ region: region });
        const codepipeline = new AWS.CodePipeline({ region: region });

        // CodeBuild Projects
        try {
            const projects = await codebuild.listProjects().promise();
            for (const projectName of projects.projects) {
                const projectRes = await codebuild.batchGetProjects({ names: [projectName] }).promise();
                const project = projectRes.projects[0];
                addInventory('devops', 'CloudBuild', project.name, 'CodeBuild Project', `Runtime: ${project.environment.type}`, 'Build pipeline');

                // Check for environment variables (potential secrets)
                const envVars = project.environment.environmentVariables || [];
                const sensitiveKeywords = ['KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'AUTH'];
                envVars.forEach(v => {
                    const isSensitive = sensitiveKeywords.some(kw => v.name.toUpperCase().includes(kw));
                    if (isSensitive && v.type !== 'PARAMETER_STORE' && v.type !== 'SECRETS_MANAGER') {
                        addVuln('devops', project.name, `Potential secret found in plaintext environment variable: ${v.name}`, 'High', 'Use AWS Secrets Manager or Parameter Store for sensitive values.');
                    }
                });

                // Privilege Escalation Check
                if (project.serviceRole.includes('Admin')) {
                    addVuln('devops', project.name, 'Build project uses highly privileged service role.', 'Medium', 'Use a custom role with minimal permissions.');
                } else {
                    markSecure('devops');
                }
            }
        } catch (e) {}

        // CodePipeline
        try {
            const pipelines = await codepipeline.listPipelines().promise();
            for (const p of pipelines.pipelines) {
                const pipe = await codepipeline.getPipeline({ name: p.name }).promise();
                addInventory('devops', 'CloudBuild', pipe.pipeline.name, 'CodePipeline', `Stages: ${pipe.pipeline.stages.length}`, 'CI/CD Orchestration');
                
                // Encryption check
                if (!pipe.pipeline.artifactStore.encryptionKey) {
                    addVuln('devops', pipe.pipeline.name, 'Pipeline artifact store not encrypted with KMS.', 'Medium', 'Configure a Customer Managed Key (CMK) for artifact encryption.');
                } else {
                    markSecure('devops');
                }
            }
        } catch (e) {}
    });

    // --- 9. Artifact Registry (ECR) ---
    await auditWrapper("Artifact Registry (ECR)", async () => {
        const ecr = new AWS.ECR({ region: region });

        try {
            const repos = await ecr.describeRepositories().promise();
            for (const repo of repos.repositories) {
                addInventory('artifacts', 'Registry', repo.repositoryName, 'ECR Repository', `URI: ${repo.repositoryUri}`, 'Container registry');

                // Image Scanning
                if (!repo.imageScanningConfiguration || !repo.imageScanningConfiguration.scanOnPush) {
                    addVuln('artifacts', repo.repositoryName, 'ECR scan on push is disabled.', 'Medium', 'Enable scan on push for vulnerability detection.');
                } else {
                    markSecure('artifacts');
                }

                // Tag Immutability
                if (repo.imageTagMutability !== 'IMMUTABLE') {
                    addVuln('artifacts', repo.repositoryName, 'Image tags are mutable.', 'Low', 'Set tag mutability to IMMUTABLE to prevent image overwrites.');
                } else {
                    markSecure('artifacts');
                }

                // Encryption
                if (repo.encryptionConfiguration && repo.encryptionConfiguration.encryptionType !== 'KMS') {
                    addVuln('artifacts', repo.repositoryName, 'Repository not encrypted with KMS.', 'Low', 'Use KMS encryption for container images.');
                } else {
                    markSecure('artifacts');
                }
            }
        } catch (e) {}
    });

    logCallback("AWS Audit Complete!");
    return results;
}

module.exports = { runAWSAudit };
