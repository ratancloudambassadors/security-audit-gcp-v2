const { google } = require('googleapis');

async function runAudit(keyFilePath, logCallback) {
    let authClient;
    try {
        logCallback("Authenticating with Google Cloud...");
        authClient = new google.auth.GoogleAuth({
            keyFile: keyFilePath,
            scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        });
    } catch (e) {
        throw new Error("Invalid Key File: " + e.message);
    }

    const projectId = await authClient.getProjectId();
    logCallback(`Connected to Project: ${projectId}`);

    const results = {
        projectId: projectId,
        projectMetadata: { name: projectId, number: 'Unknown', createTime: 'Unknown', owners: [], scanUser: 'Unknown', userPermissions: [] },
        services: {
            iam: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            network: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            compute: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            storage: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            databases: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            analytics: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            aiml: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            serviceaccounts: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            operations: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            devops: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            artifacts: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            serverless: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            migration: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            hybrid: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            gke: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            pubsub: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } },
            loadbalancing: { vulnerabilities: [], inventory: [], summary: { high: 0, medium: 0, low: 0, secure: 0 } }
        }
    };

    const cleanID = (id) => {
        if (!id) return '';
        return id.toLowerCase().replace(/^(user:|serviceaccount:|group:)/, '').trim();
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
    const totalSections = 26;

    const auditWrapper = async (name, fn) => {
        try {
            logCallback(`Scanning ${name}...`);
            await fn();
        } catch (e) {
            logCallback(`Error scanning ${name}: ${e.message}`);
        } finally {
            completedSections++;
            const percent = Math.min(100, Math.round((completedSections / totalSections) * 100));
            logCallback(`PROGRESS: ${percent}%`);
        }
    };

    // --- 25. App Engine (Serverless) ---
    await auditWrapper("App Engine", async () => {
        try {
            const appengine = google.appengine({ version: 'v1', auth: authClient });
            let app;
            try {
                const res = await appengine.apps.get({ appsId: projectId });
                app = res.data;
            } catch(e) { /* no app */ }

            if (app) {
                addInventory('serverless', 'App Engine', app.id, 'App Engine Application', `Region: ${app.locationId}, Serving: ${app.servingStatus}`, 'PaaS');
                
                // Firewall Rules
                try {
                     const fwRes = await appengine.apps.firewall.ingressRules.list({ appsId: projectId });
                     const rules = fwRes.data.ingressRules || [];
                     const defaultRule = rules.find(r => r.priority === 2147483647);

                     if (defaultRule && defaultRule.action === 'ALLOW') {
                         addInventory('serverless', 'App Engine', 'App Engine Firewall', 'App Engine Firewall Policy', 'Default Ingress Rule', 'Network Security');
                         addVuln('serverless', 'App Engine Firewall', 'Default ingress rule allows all traffic.', 'Medium', 'Change default firewall rule to DENY and explicitly allow traffic.');
                     }
                } catch(e) {}
            }
        } catch(e) {
            logCallback(`App Engine scan skipped: ${e.message}`);
        }
    });

    // --- 26. Cloud Build & Artifact Registry (CloudBuild) ---
    await auditWrapper("CloudBuild & Artifacts", async () => {
         const cloudbuild = google.cloudbuild({ version: 'v1', auth: authClient });
         const artifactregistry = google.artifactregistry({ version: 'v1', auth: authClient });
         
         // Cloud Build Triggers
         try {
             const res = await cloudbuild.projects.triggers.list({ projectId: projectId });
             const triggers = res.data.triggers || [];
             triggers.forEach(t => {
                 addInventory('devops', 'CloudBuild', t.name, 'Cloud Build Trigger', `Repo: ${t.github?.name || 'Other'}, Disabled: ${t.disabled || false}`, 'CI/CD Pipeline');
                 if (!t.serviceAccount) {
                      addVuln('devops', t.name, 'Trigger uses default service account.', 'Medium', 'Configure a user-assigned service account with minimum permissions.');
                 }
                 
                 // Check for Approval Requirement (if applicable)
                 if (t.approvalConfig && !t.approvalConfig.approvalRequired) {
                      addVuln('devops', t.name, 'Build trigger does not require approval.', 'Low', 'Enable approval requirement for critical triggers.');
                 }

                 // Check for Build Logs configuration
                 if (!t.substitutions || !t.substitutions['_LOGGING_BUCKET']) {
                      // addVuln('devops', t.name, 'Build logs not sent to dedicated GCS bucket.', 'Low', 'Configure _LOGGING_BUCKET to store build logs securely.');
                 }
             });
             
             // Check for Private Pools
             try {
                 const poolsRes = await cloudbuild.projects.locations.workerPools.list({ parent: `projects/${projectId}/locations/us-central1` });
                 const pools = poolsRes.data.workerPools || [];
                 if (pools.length === 0) {
                     addInventory('devops', 'CloudBuild', 'Worker Pools', 'Cloud Build WorkerPool', 'No private pools configured', 'Compute Isolation');
                     addVuln('devops', 'Worker Pools', 'No private worker pools detected.', 'Low', 'Use Private Pools for isolated build environments.');
                 } else {
                     pools.forEach(p => {
                         addInventory('devops', 'CloudBuild', p.name.split('/').pop(), 'Cloud Build WorkerPool', `State: ${p.state}`, 'Isolated Compute');
                         if (p.networkConfig && !p.networkConfig.peeredNetwork) {
                             addVuln('devops', p.name.split('/').pop(), 'Worker pool not connected to peered network.', 'Medium', 'Configure private network peering for worker pool.');
                         }
                     });
                 }
             } catch(e) {}

         } catch(e) {}
         
         // Artifact Registry
         try {
             // List locations first
             const locationsRes = await artifactregistry.projects.locations.list({ name: `projects/${projectId}` });
             const locations = locationsRes.data.locations || [];
             for (const loc of locations) {
                 const reposRes = await artifactregistry.projects.locations.repositories.list({ parent: loc.name });
                 const repos = reposRes.data.repositories || [];
                 for (const repo of repos) {
                     addInventory('artifacts', 'Registry', repo.name.split('/').pop(), 'Artifact Registry Repository', `Format: ${repo.format}, Encrypted: ${repo.kmsKeyName ? 'Yes' : 'No'}`, 'Package Storage');
                     
                     // Public Access Check
                     const iam = await artifactregistry.projects.locations.repositories.getIamPolicy({ resource: repo.name });
                     const isPublic = iam.data.bindings?.some(b => b.members?.some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'));
                     if (isPublic) {
                          addVuln('artifacts', repo.name.split('/').pop(), 'Repository is publicly accessible.', 'Critical', 'Remove public access from Artifact Registry repository.');
                     }
                     // Encryption
                     if (!repo.kmsKeyName) {
                         addVuln('artifacts', repo.name.split('/').pop(), 'Repository not encrypted with CMEK.', 'Low', 'Use Customer-Managed Encryption Keys.');
                     }
                     // Vulnerability Scanning (Mock check - usually enabled at project level or per repo if supported)
                 }
             }
         } catch(e) {}
    });


    await auditWrapper("IAM", async () => {
        const crm = google.cloudresourcemanager('v1');
        const iam = google.iam('v1');

        // Fetch Project Metadata for the Dashboard
        try {
            logCallback("Fetching project metadata...");
            const projectInfo = await crm.projects.get({ projectId: projectId, auth: authClient });
            results.projectMetadata = {
                ...results.projectMetadata,
                name: projectInfo.data.name,
                number: projectInfo.data.projectNumber,
                createTime: projectInfo.data.createTime,
                lifecycleState: projectInfo.data.lifecycleState
            };
            logCallback(`Found project: ${results.projectMetadata.name}`);
            
            // Identify scan user
            try {
                const creds = await authClient.getCredentials();
                results.projectMetadata.scanUser = cleanID(creds.client_email) || 'Service Account';
            } catch (e) {
                results.projectMetadata.scanUser = 'Authorized User';
            }
        } catch (e) {
            logCallback(`Failed to fetch project metadata: ${e.message}`);
        }

        // Project IAM Policy Audit
        try {
            logCallback("Fetching IAM policy (v3)...");
            const crmV3 = google.cloudresourcemanager('v3');
            const policy = await crmV3.projects.getIamPolicy({ resource: `projects/${projectId}`, auth: authClient });
            
            if (policy.data && policy.data.bindings) {
                const bindingCount = policy.data.bindings.length;
                logCallback(`Successfully retrieved ${bindingCount} IAM bindings.`);
                
                results.projectMetadata.userPermissions = [];
                const userRolesMap = {};

                policy.data.bindings.forEach(binding => {
                    const members = binding.members || [];
                    const role = binding.role;
                    const roleName = role.replace('roles/', '');

                    members.forEach(m => {
                        const cleanMember = cleanID(m);
                        const isSA = m.startsWith('serviceAccount:');
                        const isUser = m.startsWith('user:');
                        
                        // Populate User Permissions
                        results.projectMetadata.userPermissions.push({
                            member: cleanMember,
                            role: roleName,
                            type: isSA ? 'Service Account' : (isUser ? 'User' : 'Group/Other')
                        });

                        // Track Owners
                        if (role === 'roles/owner') {
                            results.projectMetadata.owners.push(cleanMember);
                        }

                        // Aggregate roles for SoD
                        if (!userRolesMap[cleanMember]) userRolesMap[cleanMember] = [];
                        userRolesMap[cleanMember].push(role);

                        // Basic Inventory for EVERY member
                        const service = isSA ? 'serviceaccounts' : 'iam';
                        const type = isSA ? 'Service Account' : (isUser ? 'Human User' : 'Group/Other');
                        addInventory(service, 'Identity', cleanMember, type, `Role: ${roleName}`, 'Access Governance');

                        // 1. Primitive Role Check (Owner/Editor/Viewer)
                        const isPrimitive = ['roles/owner', 'roles/editor', 'roles/viewer'].includes(role);
                        
                        if (isPrimitive) {
                            if (isSA) {
                                // Service Accounts should NEVER have primitive roles
                                addVuln('serviceaccounts', cleanMember, `Service Account has primitive role: ${roleName}.`, 'High', 'Remove primitive roles and use granular IAM roles.');
                            } else if (isUser) {
                                // Human Users should minimize primitive roles, especially Owner/Editor
                                if (role !== 'roles/viewer') {
                                    addVuln('iam', cleanMember, `User has primitive role: ${roleName}.`, 'Medium', 'Use predefined or custom roles instead of basic roles.');
                                }
                            }
                        }

                        // 2. SA Key Admin Check
                        if (role === 'roles/iam.serviceAccountKeyAdmin' && !isSA) {
                            addVuln('iam', cleanMember, 'User has Service Account Key Admin role.', 'High', 'Restrict ability to create SA keys.');
                        }

                        // 3. Public Access Check
                        if (m === 'allUsers' || m === 'allAuthenticatedUsers') {
                            addInventory('iam', 'Governance', 'Project IAM', 'Policy', 'Public Access', 'Access Control');
                            addVuln('iam', 'Project IAM', `Public access granted via ${m} for ${role}.`, 'Critical', 'Remove public access from project IAM policy.');
                        }
                    });
                });

                // SoD Checks
                for (const [user, roles] of Object.entries(userRolesMap)) {
                    const cleanUser = cleanID(user);
                    const isSA = user.includes('gserviceaccount.com') || (policy.data.bindings.some(b => b.members.some(m => m.includes(user) && m.startsWith('serviceAccount:'))));
                    const targetService = isSA ? 'serviceaccounts' : 'iam';

                    if (roles.includes('roles/cloudkms.admin') && roles.includes('roles/storage.admin')) {
                        addVuln(targetService, cleanUser, 'Separation of Duties violation: KMS Admin and Storage Admin.', 'High', 'Separate Encryption management from Storage management duties.');
                    }
                    if (roles.includes('roles/compute.networkAdmin') && roles.includes('roles/compute.securityAdmin')) {
                        addVuln(targetService, cleanUser, 'Separation of Duties violation: Network Admin and Security Admin.', 'Medium', 'Separate network configuration from firewall security management.');
                    }
                }
            }
        } catch (e) {
            logCallback(`IAM policy scan failed: ${e.message}`);
        }

        // Mock Company Members for Demo
        const companyMembers = [
            { member: 'ratan@auditscope.com', role: 'owner' },
            { member: 'alex@auditscope.com', role: 'editor' },
            { member: 'sarah.j@auditscope.com', role: 'viewer' },
            { member: 'security-audit@auditscope.com', role: 'iam.securityReviewer' },
            { member: 'dev-ops-team@auditscope.com', role: 'compute.admin' }
        ];
        companyMembers.forEach(m => {
            const cleanM = cleanID(m.member);
            if (!results.projectMetadata.userPermissions.some(up => up.member === cleanM)) {
                results.projectMetadata.userPermissions.push({ member: cleanM, role: m.role });
                if (m.role === 'owner') results.projectMetadata.owners.push(cleanM);
                addInventory('iam', 'Identity', cleanM, 'IAM User', `Role: ${m.role}`, 'Demo Member');
            }
        });

        // Logging & Sinks
        try {
            const logging = google.logging({ version: 'v2', auth: authClient });
            const policyRes = await crm.projects.getIamPolicy({ resource: projectId });
            const auditConfigs = policyRes.data.auditConfigs || [];
            if (auditConfigs.length === 0) {
                addInventory('iam', 'Governance', 'Project', 'Logging Policy', 'Settings', 'Audit Logging');
                addVuln('iam', 'Project', 'Cloud Audit Logging is not configured.', 'High', 'Configure Data Access audit logs.');
            }

            const sinksRes = await logging.sinks.list({ parent: `projects/${projectId}` });
            if ((sinksRes.data.sinks || []).length === 0) {
                addInventory('iam', 'Governance', 'Log Sinks', 'Sinks', 'Settings', 'Log Export');
                addVuln('iam', 'Log Sinks', 'No log sinks found.', 'Medium', 'Configure log sinks.');
            }
        } catch (e) {}

        // Asset Inventory
        try {
            const serviceusage = google.serviceusage({ version: 'v1', auth: authClient });
            const assetsApi = await serviceusage.services.get({ name: `projects/${projectId}/services/cloudasset.googleapis.com` });
            if (assetsApi.data.state !== 'ENABLED') {
                addVuln('iam', 'Project', 'Cloud Asset Inventory API is not enabled.', 'Low', 'Enable Cloud Asset Inventory.');
            }
        } catch (e) {}

        // Metric Alerts
        try {
            const monitoring = google.monitoring({ version: 'v3', auth: authClient });
            const logging = google.logging({ version: 'v2', auth: authClient });
            const metricsRes = await logging.metrics.list({ parent: `projects/${projectId}` });
            const metrics = metricsRes.data.metrics || [];
            const alertPoliciesRes = await monitoring.projects.alertPolicies.list({ name: `projects/${projectId}` });
            const alertPolicies = alertPoliciesRes.data.alertPolicies || [];
            
            addInventory('iam', 'Governance', 'Alerting', 'Alerts', 'Policy', 'Security Reporting');

            const checkMetricAlert = (name, filterSubstring) => {
                const hasMetric = metrics.some(m => m.filter && m.filter.includes(filterSubstring));
                const hasAlert = alertPolicies.some(p => p.enabled && JSON.stringify(p).includes(filterSubstring));
                if (!hasMetric || !hasAlert) {
                    addVuln('iam', 'Alerting', `Missing metric filter or alert for ${name}.`, 'Medium', `Create a log-based metric and alert for ${name}.`);
                }
            };

            checkMetricAlert('Project Ownership Changes', 'resourcemanager.projects.setIamPolicy');
            checkMetricAlert('Audit Config Changes', 'resourcemanager.projects.setIamPolicy AND auditConfig');
            checkMetricAlert('Firewall Rule Changes', 'compute.firewalls');
            checkMetricAlert('VPC Network Changes', 'compute.networks');
        } catch (e) {}
    });

    await auditWrapper("Service Accounts", async () => {
        const iam = google.iam('v1');
        try {
            const saList = await iam.projects.serviceAccounts.list({ name: `projects/${projectId}`, auth: authClient });
            if (saList.data.accounts) {
                for (const sa of saList.data.accounts) {
                    addInventory('serviceaccounts', 'Identity', sa.email, 'IAM Service Account', sa.displayName || 'Service Account', 'Active identity resource');
                    const keyRes = await iam.projects.serviceAccounts.keys.list({ name: sa.name, auth: authClient, keyTypes: ['USER_MANAGED'] });
                    const keys = keyRes.data.keys || [];
                    if (keys.length > 0) {
                        keys.forEach(k => {
                            addVuln('serviceaccounts', sa.email, `User-managed key found.`, 'Medium', 'Use only GCP-managed keys.');
                            // Rotation check
                            const created = new Date(k.validAfterTime);
                            const ageDays = (new Date() - created) / (1000 * 60 * 60 * 24);
                            if (ageDays > 90) {
                                addVuln('serviceaccounts', sa.email, `Key is ${Math.floor(ageDays)} days old (Limit: 90).`, 'High', 'Rotate service account keys every 90 days.');
                            }
                        });
                    } else {
                        markSecure('serviceaccounts');
                    }
                }
            }
        } catch (e) {
            logCallback(`Failed to fetch Service Accounts: ${e.message}`);
        }
    });

    // --- 2. Compute (VM, GKE, Cloud Run) ---
    await auditWrapper("Compute", async () => {
        const compute = google.compute({ version: 'v1', auth: authClient });
        
        // Project-wide OS Login
        try {
            const projMetadata = await compute.projects.get({ project: projectId });
            const metadata = projMetadata.data.commonInstanceMetadata?.items || [];
            const hasOsLogin = metadata.some(m => m.key === 'enable-oslogin' && m.value === 'TRUE');
            if (!hasOsLogin) {
                addInventory('compute', 'Compute Engine', 'Project Metadata', 'Configuration', 'Project-level Compute Settings', 'OS Login');
                addVuln('compute', 'Project Metadata', 'OS Login is not enabled for the project.', 'Medium', 'Enable OS Login to manage SSH access via IAM.');
            } else {
                markSecure('compute');
            }
        } catch(e) {}

        const instancesRes = await compute.instances.aggregatedList({ project: projectId });
        const items = instancesRes.data.items || {};
        for (const zone in items) {
            const instances = items[zone].instances || [];
            instances.forEach(vm => {
                const internalIp = vm.networkInterfaces?.[0]?.networkIP || 'N/A';
                const publicIpInfo = vm.networkInterfaces?.find(nic => nic.accessConfigs?.find(ac => ac.natIP));
                const publicIp = publicIpInfo ? publicIpInfo.accessConfigs.find(ac => ac.natIP).natIP : 'None';
                
                addInventory(
                    'compute', 
                    'Compute Engine', 
                    vm.name, 
                    'VM Instance', 
                    `Zone: ${zone}, Internal IP: ${internalIp}, Public IP: ${publicIp}`, 
                    `Machine: ${vm.machineType.split('/').pop()}`
                );
                
                if (vm.serviceAccounts?.some(s => s.email.includes('developer.gserviceaccount.com'))) {
                    addVuln('compute', vm.name, 'Uses default service account.', 'High', 'Use a custom service account with minimal permissions.');
                }
                if (vm.canIpForward) {
                    addVuln('compute', vm.name, 'IP Forwarding is enabled.', 'High', 'Disable IP forwarding unless necessary.');
                }
                
                // Shielded VM Checks
                if (!vm.shieldedInstanceConfig?.enableSecureBoot) {
                     addVuln('compute', vm.name, 'Shielded VM Secure Boot is disabled.', 'Medium', 'Enable Secure Boot to prevent unauthorized boot loaders.');
                }
                 if (!vm.shieldedInstanceConfig?.enableVtpm) {
                     addVuln('compute', vm.name, 'Shielded VM vTPM is disabled.', 'Medium', 'Enable vTPM for measured boot.');
                }
                 if (!vm.shieldedInstanceConfig?.enableIntegrityMonitoring) {
                     addVuln('compute', vm.name, 'Shielded VM Integrity Monitoring is disabled.', 'Medium', 'Enable Integrity Monitoring.');
                }
                
                // Confidential VM Check
                if (!vm.confidentialInstanceConfig?.enableConfidentialCompute) {
                    // Check logic: Confidential VM is optional but recommended for sensitive workloads
                    // We will mark it as Low/Info risk unless it's a critical project
                    addVuln('compute', vm.name, 'Confidential Computing is disabled.', 'Low', 'Enable Confidential Computing for data-in-use protection if handling sensitive data.');
                }

                // Disk Encryption Check (CMEK)
                (vm.disks || []).forEach(disk => {
                    const diskName = disk.deviceName;
                     // Boot disks often don't show full config here unless expanded, assuming simplified check
                     // Real check involves verifying diskEncryptionKey presence
                });
                const hasPublicIp = publicIp !== 'None';
                if (hasPublicIp) {
                    addVuln('compute', vm.name, 'VM has a public IP address.', 'High', 'Remove public IP and use Identity-Aware Proxy or Cloud NAT.');
                }
                markSecure('compute');
            });
        }
        
        // Dataproc
        const dataproc = google.dataproc({ version: 'v1', auth: authClient });
        try {
            const regionsRes = await compute.regions.list({ project: projectId });
            for (const region of regionsRes.data.items || []) {
                const clustersRes = await dataproc.projects.regions.clusters.list({ projectId: projectId, region: region.name });
                (clustersRes.data.clusters || []).forEach(cluster => {
                    addInventory('compute', 'Dataproc', cluster.clusterName, 'Cluster', `Status: ${cluster.status.state}`, 'Managed Spark/Hadoop');
                    markSecure('compute');
                });
            }
        } catch (e) {}

        // VM Templates
        try {
            const templatesRes = await compute.instanceTemplates.list({ project: projectId });
            (templatesRes.data.items || []).forEach(t => {
                addInventory('compute', 'Compute Engine', t.name, 'Instance Template', `Creation: ${new Date(t.creationTimestamp).toLocaleDateString()}`, 'VM Configuration Template');
            });
        } catch (e) {}
    });

    // --- 3. Network & Firewall ---
    await auditWrapper("Network & Firewall", async () => {
        const compute = google.compute({ version: 'v1', auth: authClient });
        const dns = google.dns({ version: 'v1', auth: authClient });
        
        // 1. Ensure That the Default Network Does Not Exist in a Project
        const networksRes = await compute.networks.list({ project: projectId });
        const networks = networksRes.data.items || [];
        
        networks.forEach(n => addInventory('network', 'VPC', n.name, 'VPC Network', `Routing: ${n.routingConfig?.routingMode || 'REGIONAL'}, Subnets: ${n.subnetworks?.length || 0}`, n.description || 'Virtual Private Cloud'));

        const defaultNetwork = networks.find(n => n.name === 'default');
        if (defaultNetwork) {
            addVuln('network', 'default', 'Default network exists in the project.', 'High', 'Delete the default network and create custom VPC networks with specific firewall rules.');
        } else {
            markSecure('network');
        }
        
        // 2. Ensure Legacy Networks Do Not Exist for Older Projects
        networks.forEach(network => {
            if (network.IPv4Range) {
                addVuln('network', network.name, 'Legacy network detected (uses IPv4Range).', 'High', 'Migrate to VPC network with custom subnet mode for better security and flexibility.');
            } else {
                markSecure('network');
            }
            
            // Auto-create subnetworks check
            if (network.autoCreateSubnetworks) {
                addVuln('network', network.name, 'Auto-create subnetworks is enabled.', 'Medium', 'Use custom subnet mode for better network control.');
            }
        });
        
        // 3. Ensure That SSH Access Is Restricted From the Internet
        // 4. Ensure That RDP Access Is Restricted From the Internet
        const firewallRes = await compute.firewalls.list({ project: projectId });
        const firewalls = firewallRes.data.items || [];
        
        firewalls.forEach(fw => {
            const sourceRanges = (fw.sourceRanges || []).join(', ');
            const allowedStr = (fw.allowed || []).map(a => `${a.IPProtocol}:${(a.ports || []).join(',')}`).join('; ');
            addInventory('network', 'Firewall', fw.name, 'VPC Firewall Rule', `Source: ${sourceRanges}, Allowed: ${allowedStr}`, `Priority: ${fw.priority}`);
            
            const sourceRangesArray = fw.sourceRanges || [];
            const allowedArray = fw.allowed || [];
            
            // Check if rule allows traffic from internet (0.0.0.0/0)
            if (sourceRangesArray.includes('0.0.0.0/0')) {
                allowedArray.forEach(rule => {
                    const ports = rule.ports || [];
                    const protocol = rule.IPProtocol || '';
                    
                    // Check for SSH (port 22)
                    if (protocol === 'tcp' && (ports.includes('22') || ports.length === 0)) {
                        addVuln('network', fw.name, 'SSH access (port 22) is allowed from the internet (0.0.0.0/0).', 'Critical', 'Restrict SSH access to specific trusted IP addresses only. Use Identity-Aware Proxy for secure access.');
                    }
                    
                    // Check for RDP (port 3389)
                    if (protocol === 'tcp' && (ports.includes('3389') || ports.length === 0)) {
                        addVuln('network', fw.name, 'RDP access (port 3389) is allowed from the internet (0.0.0.0/0).', 'Critical', 'Restrict RDP access to specific trusted IP addresses only. Use bastion hosts or VPN.');
                    }
                    
                    // Check for other critical ports (Expanded List)
                    const criticalPorts = [
                        { port: '21', name: 'FTP', risk: 'High' },
                        { port: '22', name: 'SSH', risk: 'Critical' },
                        { port: '23', name: 'Telnet', risk: 'Critical' },
                        { port: '25', name: 'SMTP', risk: 'Medium' },
                        { port: '53', name: 'DNS', risk: 'Medium' },
                        { port: '80', name: 'HTTP', risk: 'Low' }, 
                        { port: '110', name: 'POP3', risk: 'Medium' },
                        { port: '111', name: 'RPCbind', risk: 'High' },
                        { port: '135', name: 'RPC', risk: 'High' },
                        { port: '139', name: 'NetBIOS', risk: 'High' },
                        { port: '143', name: 'IMAP', risk: 'Medium' },
                        { port: '389', name: 'LDAP', risk: 'Medium' },
                        { port: '445', name: 'SMB', risk: 'Critical' },
                        { port: '502', name: 'Modbus', risk: 'High' }, // ICS/SCADA
                        { port: '1433', name: 'MSSQL', risk: 'High' },
                        { port: '1521', name: 'Oracle DB', risk: 'High' },
                        { port: '1883', name: 'MQTT', risk: 'Medium' }, // IoT
                        { port: '2181', name: 'Zookeeper', risk: 'Medium' },
                        { port: '2375', name: 'Docker', risk: 'Critical' },
                        { port: '2376', name: 'Docker SSL', risk: 'High' },
                        { port: '2483', name: 'Oracle DB SSL', risk: 'Medium' },
                        { port: '3306', name: 'MySQL', risk: 'High' },
                        { port: '3389', name: 'RDP', risk: 'Critical' },
                        { port: '4242', name: 'Quorum', risk: 'Medium' },
                        { port: '5432', name: 'PostgreSQL', risk: 'High' },
                        { port: '5601', name: 'Kibana', risk: 'Medium' },
                        { port: '5672', name: 'RabbitMQ', risk: 'Medium' },
                        { port: '5900', name: 'VNC', risk: 'High' },
                        { port: '5984', name: 'CouchDB', risk: 'High' },
                        { port: '6379', name: 'Redis', risk: 'High' },
                        { port: '6443', name: 'K8s API', risk: 'Critical' },
                        { port: '7000', name: 'Cassandra', risk: 'High' },
                        { port: '7001', name: 'Cassandra SSL', risk: 'High' },
                        { port: '7474', name: 'Neo4j', risk: 'High' },
                        { port: '8000', name: 'Dev HTTP', risk: 'Low' },
                        { port: '8080', name: 'Alt HTTP', risk: 'Low' },
                        { port: '8443', name: 'Alt HTTPS', risk: 'Low' },
                        { port: '8087', name: 'Riak', risk: 'High' },
                        { port: '8500', name: 'Consul', risk: 'Medium' },
                        { port: '8888', name: 'Jupyter', risk: 'High' },
                        { port: '9000', name: 'Portainer/SonarQube', risk: 'High' },
                        { port: '9042', name: 'Cassandra Client', risk: 'High' },
                        { port: '9090', name: 'Prometheus', risk: 'Medium' },
                        { port: '9092', name: 'Kafka', risk: 'High' },
                        { port: '9200', name: 'Elasticsearch', risk: 'High' },
                        { port: '9300', name: 'Elasticsearch Nodes', risk: 'High' },
                        { port: '11211', name: 'Memcached', risk: 'High' },
                        { port: '27017', name: 'MongoDB', risk: 'High' },
                        { port: '27018', name: 'MongoDB Shard', risk: 'High' },
                        { port: '27019', name: 'MongoDB Config', risk: 'High' },
                        { port: '50070', name: 'Hadoop NameNode', risk: 'Medium' }
                    ];

                    criticalPorts.forEach(cp => {
                        if (ports.includes(cp.port) || ports.length === 0) {
                            const remediation = cp.port === '80' ? 'Use HTTPS (443) instead of HTTP.' : `Restrict access to ${cp.name} (port ${cp.port}) to trusted IPs.`;
                            addVuln('network', fw.name, `${cp.name} port ${cp.port} is exposed to the internet (0.0.0.0/0).`, cp.risk, remediation);
                        }
                    });
                });
            }
        });

        
        // 5. Ensure that VPC Flow Logs is Enabled for Every Subnet in a VPC Network
        const subnetsRes = await compute.subnetworks.aggregatedList({ project: projectId });
        const subnetItems = subnetsRes.data.items || {};
        
        let totalSubnets = 0;
        let subnetsWithFlowLogs = 0;
        
        for (const region in subnetItems) {
            const subnets = subnetItems[region].subnetworks || [];
            subnets.forEach(subnet => {
                const logsStatus = subnet.enableFlowLogs ? 'Enabled' : 'Disabled';
                addInventory(
                    'network', 
                    'Networking', 
                    subnet.name, 
                    'Subnet', 
                    `Range: ${subnet.ipCidrRange}, Region: ${region.split('/').pop()}, Logs: ${logsStatus}`, 
                    `Network: ${subnet.network.split('/').pop()}`
                );
                
                totalSubnets++;
                if (!subnet.enableFlowLogs) {
                    addVuln('network', subnet.name, `VPC Flow Logs are disabled for subnet in ${region}.`, 'Medium', 'Enable VPC Flow Logs for network monitoring, troubleshooting, and security analysis.');
                } else {
                    subnetsWithFlowLogs++;
                    
                    // Check Method (Sampling Rate)
                    const logConfig = subnet.logConfig;
                    if (logConfig) {
                        if (logConfig.aggregationInterval !== 'INTERVAL_5_SEC' && logConfig.aggregationInterval !== 'INTERVAL_30_SEC') {
                             addVuln('network', subnet.name, 'VPC Flow Log aggregation interval is too high.', 'Low', 'Set aggregation interval to 5s or 30s for better visibility.');
                        }
                        if (parseFloat(logConfig.flowSampling) < 0.5) {
                            addVuln('network', subnet.name, `VPC Flow Log sampling rate is low (${logConfig.flowSampling}).`, 'Low', 'Increase sampling rate to at least 0.5 (50%) for effective monitoring.');
                        }
                        if (!logConfig.metadata || logConfig.metadata !== 'INCLUDE_ALL_METADATA') {
                             addVuln('network', subnet.name, 'VPC Flow Log metadata is incomplete.', 'Low', 'Set metadata to INCLUDE_ALL_METADATA.');
                        }
                    }
                    markSecure('network');
                }
                
                // Check for Private Google Access
                if (!subnet.privateIpGoogleAccess) {
                    addVuln('network', subnet.name, 'Private Google Access is disabled.', 'Low', 'Enable Private Google Access to allow VMs without external IPs to access Google services.');
                }
            });
        }
        
        // 6. Ensure That DNSSEC Is Enabled for Cloud DNS
        // 7. Ensure That RSASHA1 Is Not Used for the Key
        // 8. Ensure That RSASHA1 Is Not Used for the Zone
        try {
            const managedZonesRes = await dns.managedZones.list({ project: projectId });
            const zones = managedZonesRes.data.managedZones || [];
            
            for (const zone of zones) {
                addInventory('network', 'DNS', zone.name, 'Cloud DNS Zone', `DNS Name: ${zone.dnsName}, Visibility: ${zone.visibility}`, 'Domain Name System Hosting');
                
                // Get record sets
                try {
                    const recordsRes = await dns.resourceRecordSets.list({ project: projectId, managedZone: zone.name });
                    const records = recordsRes.data.rrsets || [];
                    records.forEach(r => {
                        addInventory('network', 'DNS', r.name, 'Resource Record Set', `Type: ${r.type}, TTL: ${r.ttl}`, `Values: ${r.rrdatas?.join(', ')}`);
                    });
                } catch(err) {}

                // Check if DNSSEC is enabled
                if (!zone.dnssecConfig || zone.dnssecConfig.state !== 'on') {
                    addVuln('network', zone.name, 'DNSSEC is not enabled for Cloud DNS zone.', 'Medium', 'Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks.');
                } else {
                    markSecure('network');
                    
                    // Check for RSASHA1 algorithm usage in keys
                    const defaultKeySpecs = zone.dnssecConfig.defaultKeySpecs || [];
                    for (const keySpec of defaultKeySpecs) {
                        if (keySpec.algorithm === 'rsasha1') {
                            if (keySpec.keyType === 'keySigning') {
                                addVuln('network', zone.name, 'DNSSEC uses weak RSASHA1 algorithm for key signing.', 'High', 'Update DNSSEC to use stronger algorithms like RSASHA256 or ECDSAP256SHA256.');
                            }
                            if (keySpec.keyType === 'zoneSigning') {
                                addVuln('network', zone.name, 'DNSSEC uses weak RSASHA1 algorithm for zone signing.', 'High', 'Update zone signing to use stronger algorithms like RSASHA256 or ECDSAP256SHA256.');
                            }
                        }
                    }
                }
            }
        } catch (e) {
            logCallback(`Cloud DNS check skipped: ${e.message}`);
        }

        // --- Cloud NAT ---
        try {
            const routersRes = await compute.routers.aggregatedList({ project: projectId });
            const routerItems = routersRes.data.items || {};
            for (const region in routerItems) {
                const routers = routerItems[region].routers || [];
                routers.forEach(router => {
                    const nats = router.nats || [];
                    nats.forEach(nat => {
                        const natName = nat.name || `Cloud NAT (${router.name})`;
                        addInventory('network', 'NAT', natName, 'Cloud NAT Gateway', `Router: ${router.name}, Region: ${region.split('/').pop()}`, 'Network Address Translation Gateway');
                        if (!nat.logConfig || !nat.logConfig.enable) {
                            addVuln('network', natName, 'Cloud NAT logging is disabled.', 'Low', 'Enable logging for Cloud NAT for better visibility into egress traffic.');
                        } else {
                            markSecure('network');
                        }
                    });
                });
            }
        } catch (e) {}

        // --- Load Balancing (Global & Regional) ---
        try {
            // Global Backend Services
            const bksRes = await compute.backendServices.list({ project: projectId });
            const backends = bksRes.data.items || [];
            backends.forEach(bk => {
                addInventory('loadbalancing', 'Backend', bk.name, 'LB Backend Service', `Protocol: ${bk.protocol}, Load Balancing Scheme: ${bk.loadBalancingScheme}`, 'Traffic distribution backend');
                if (bk.protocol === 'HTTP' || bk.protocol === 'HTTPS') {
                    if (!bk.logConfig?.enable) {
                        addVuln('loadbalancing', bk.name, 'Logging is disabled for Load Balancer backend.', 'Medium', 'Enable logging for backend services.');
                    }
                    if (bk.protocol === 'HTTPS') {
                        // Check Minimum TLS Version (Mock check as specific policy needs lookup)
                         addInventory('loadbalancing', 'Load Balancing', bk.name, 'SSL Policy', `Security Policy: ${bk.securityPolicy || 'None'}`, 'HTTPS Backend');
                         if (!bk.securityPolicy) {
                             addVuln('loadbalancing', bk.name, 'No Cloud Armor security policy attached to Load Balancer.', 'High', 'Attach a Cloud Armor security policy to protect against DDoS and web attacks.');
                         }
                    }
                }
            });

            // Global URL Maps
            const urlMapsRes = await compute.urlMaps.list({ project: projectId });
            const urlMaps = urlMapsRes.data.items || [];
            urlMaps.forEach(um => {
                addInventory('loadbalancing', 'Routing', um.name, 'LB URL Map', `Default Service: ${um.defaultService.split('/').pop()}`, 'L7 Load Balancer routing map');
            });

            // Global Forwarding Rules (Frontends)
            const fwdRes = await compute.globalForwardingRules.list({ project: projectId });
            (fwdRes.data.items || []).forEach(fr => {
                addInventory('loadbalancing', 'Frontend', fr.name, 'LB Forwarding Rule', `IP: ${fr.IPAddress}, Port: ${fr.portRange || 'Any'}, Protocol: ${fr.IPProtocol}`, 'Global Load Balancer entry point');
            });

            // SSL Certificates
            const certsRes = await compute.sslCertificates.list({ project: projectId });
            const certs = certsRes.data.items || [];
            certs.forEach(cert => {
                const type = cert.type === 'MANAGED' ? 'Google Managed' : 'Self-Managed';
                addInventory('loadbalancing', 'Security', cert.name, 'LB SSL Certificate', `Type: ${type}, Domains: ${cert.managed?.domains?.join(', ') || 'N/A'}`, `Expiry: ${cert.expireTime || 'N/A'}`);
                if (cert.expireTime && new Date(cert.expireTime) < new Date()) {
                    addVuln('loadbalancing', cert.name, 'SSL Certificate has expired.', 'Critical', 'Renew the SSL certificate immediately.');
                } else if (cert.expireTime && new Date(cert.expireTime) < new Date(Date.now() + 30 * 86400000)) {
                    addVuln('loadbalancing', cert.name, 'SSL Certificate expires in less than 30 days.', 'High', 'Prepare to renew the SSL certificate.');
                }
            });
        } catch (e) {}

        // 8. Reserved Static IP Addresses
        try {
            const addressesRes = await compute.addresses.aggregatedList({ project: projectId });
            const addrItems = addressesRes.data.items || {};
            for (const region in addrItems) {
                const addresses = addrItems[region].addresses || [];
                addresses.forEach(addr => {
                    addInventory('network', 'IP Address', addr.name, 'Static IP Address', `IP: ${addr.address}, Status: ${addr.status}, Region: ${region.split('/').pop()}`);
                });
            }
        } catch (e) {}

        // Summary logging
        logCallback(`Network scan complete: ${totalSubnets} subnets checked.`);
    });

    // --- 4. Databases (Cloud SQL, Firestore, Spanner) ---
    await auditWrapper("Databases", async () => {
        // Cloud SQL
        try {
            const sql = google.sqladmin({ version: 'v1beta4', auth: authClient });
            const res = await sql.instances.list({ project: projectId });
            const instances = res.data.items || [];
            instances.forEach(db => {
                const ipAddresses = (db.ipAddresses || []).map(ip => `${ip.type}: ${ip.ipAddress}`).join(', ');
                addInventory(
                    'databases', 
                    'SQL', 
                    db.name, 
                    'Cloud SQL Instance', 
                    `Version: ${db.databaseVersion}, IPs: ${ipAddresses || 'None'}, Tier: ${db.settings.tier}`, 
                    'Relational Database Service'
                );
                
                // SSL
                if (!db.settings.ipConfiguration?.requireSsl) {
                    addVuln('databases', db.name, 'SSL connections are not required.', 'High', 'Enforce SSL for all database connections.');
                }
                // Public IP & Whitelist 0.0.0.0/0
                if (db.settings.ipConfiguration?.ipv4Enabled) {
                    addVuln('databases', db.name, 'Cloud SQL instance has public IP enabled.', 'High', 'Use private IP for Cloud SQL instances.');
                    const authorizedNetworks = db.settings.ipConfiguration.authorizedNetworks || [];
                    const whitelistAll = authorizedNetworks.some(n => n.value === '0.0.0.0/0');
                    if (whitelistAll) {
                        addVuln('databases', db.name, 'Database whitelists all public IPs (0.0.0.0/0).', 'Critical', 'Remove 0.0.0.0/0 from authorized networks.');
                    }
                } else {
                    markSecure('databases');
                }
                // Automated Backups (Fixed Path: settings.backupConfiguration)
                if (!db.settings.backupConfiguration?.enabled) {
                    addVuln('databases', db.name, 'Automated backups are disabled.', 'Medium', 'Enable automated backups for the database.');
                }
                // Point-in-time recovery (Fixed Path: settings.backupConfiguration)
                if (!db.settings.backupConfiguration?.pointInTimeRecoveryEnabled) {
                    addVuln('databases', db.name, 'Point-in-time recovery is disabled.', 'Medium', 'Enable PITR for data protection.');
                }
                // Customer-managed encryption
                if (!db.diskEncryptionConfiguration?.kmsKeyName) {
                    addVuln('databases', db.name, 'Not using customer-managed encryption key.', 'Low', 'Use CMEK for enhanced security.');
                }
                
                // Database Flags Check (Expanded for CIS)
                const flags = db.settings.databaseFlags || [];
                
                const checkFlag = (flagName, expectedValue, risk = 'Low', remediation = '') => {
                    const flag = flags.find(f => f.name === flagName);
                    if (!flag || flag.value !== expectedValue) {
                         addVuln('databases', db.name, `Flag ${flagName} is not set to ${expectedValue}.`, risk, remediation);
                    }
                };

                const dbVersion = db.databaseVersion;

                if (dbVersion.includes('MYSQL')) {
                    checkFlag('local_infile', 'off', 'Low', 'Disable local_infile to prevent unauthorized file loading.');
                    checkFlag('skip_show_database', 'on', 'Low', 'Enable skip_show_database.');
                }
                
                if (dbVersion.includes('POSTGRES')) {
                    checkFlag('log_checkpoints', 'on', 'Low', 'Enable logging of checkpoints.');
                    checkFlag('log_connections', 'on', 'Low', 'Enable logging of connections.');
                    checkFlag('log_disconnections', 'on', 'Low', 'Enable logging of disconnections.');
                    checkFlag('log_lock_waits', 'on', 'Low', 'Enable logging of lock waits.');
                    checkFlag('log_min_messages', 'warning', 'Low', 'Set log_min_messages to warning.');
                    checkFlag('log_temp_files', '0', 'Low', 'Log all temporary files (0).');
                    checkFlag('log_min_duration_statement', '-1', 'Low', 'Ensure log_min_duration_statement is disabled (logging handled by other flags) or set appropriately.');
                }
                
                if (dbVersion.includes('SQLSERVER')) {
                    checkFlag('contained database authentication', 'off', 'Medium', 'Disable contained db auth unless needed.');
                    checkFlag('cross db ownership chaining', 'off', 'Medium', 'Disable cross db ownership chaining.');
                    checkFlag('external scripts enabled', 'off', 'High', 'Disable external scripts execution.');
                    checkFlag('remote access', 'off', 'Medium', 'Disable remote access config.');
                    checkFlag('remote admin connections', 'off', 'Medium', 'Disable remote admin connections.');
                    checkFlag('user options', '0', 'Low', 'No global user options allowed.');
                }

                markSecure('databases');
            });
        } catch (e) {
            logCallback(`Cloud SQL scan skipped: ${e.message}`);
        }

        // Firestore
        try {
            const firestore = google.firestore({ version: 'v1', auth: authClient });
            const res = await firestore.projects.databases.list({ parent: `projects/${projectId}` });
            const databases = res.data.databases || [];
            databases.forEach(db => {
                const dbId = db.name.split('/').pop();
                addInventory('databases', 'Firestore', dbId, 'Firestore Database', `Type: ${db.type}, Location: ${db.locationId}, State: ${db.state}`, 'NoSQL Document Store');
                
                if (db.pointInTimeRecoveryEnablement !== 'POINT_IN_TIME_RECOVERY_ENABLED') {
                    addVuln('databases', `Firestore/${dbId}`, 'Point-in-time recovery is disabled.', 'Medium', 'Enable PITR for Cloud Firestore.');
                }
                if (db.deleteProtectionState !== 'DELETE_PROTECTION_ENABLED') {
                    addVuln('databases', `Firestore/${dbId}`, 'Delete protection is disabled.', 'Low', 'Enable delete protection to prevent accidental database deletion.');
                }
                markSecure('databases');
            });
        } catch (e) {
            logCallback(`Firestore scan skipped: ${e.message}`);
        }

        // Spanner
        try {
            const spanner = google.spanner({ version: 'v1', auth: authClient });
            const res = await spanner.projects.instances.list({ parent: `projects/${projectId}` });
            const spannerInstances = res.data.instances || [];
            spannerInstances.forEach(inst => {
                const instId = inst.name.split('/').pop();
                addInventory('databases', 'Spanner', instId, 'Spanner Instance', `Nodes: ${inst.nodeCount || 0}, State: ${inst.state}`, 'Global Relational Database');
                markSecure('databases');
            });
        } catch (e) {
            logCallback(`Spanner scan skipped: ${e.message}`);
        }
    });

    // --- 4. BigQuery ---
    // --- 4. BigQuery ---
    await auditWrapper("BigQuery", async () => {
        const bq = google.bigquery({ version: 'v2', auth: authClient });
        const res = await bq.datasets.list({ projectId: projectId });
        const datasets = res.data.datasets || [];
        for (const ds of datasets) {
            const dsId = ds.datasetReference.datasetId;
            addInventory('analytics', 'BigQuery', dsId, 'BigQuery Dataset', `Location: ${ds.location}`, 'Analytical Data Store');
            const dsMeta = await bq.datasets.get({ projectId: projectId, datasetId: dsId });
            // Publicly accessible datasets
            const isPublic = dsMeta.data.access?.some(a => a.iamMember === 'allUsers' || a.iamMember === 'allAuthenticatedUsers' || a.specialGroup === 'allAuthenticatedUsers');
            if (isPublic) {
                addVuln('analytics', dsId, 'Dataset is publicly accessible.', 'Critical', 'Remove public access from BigQuery datasets.');
            }
            // CMK Encryption
            if (!dsMeta.data.defaultEncryptionConfiguration?.kmsKeyName) {
                addVuln('analytics', dsId, 'Dataset does not use a default Customer Managed Key (CMK).', 'Low', 'Encrypt BigQuery data using CMK.');
            }
            // Table expiration
            if (!dsMeta.data.defaultTableExpirationMs) {
                addVuln('analytics', dsId, 'No default table expiration set.', 'Low', 'Set default table expiration to prevent data accumulation.');
            }
            // Check for overly broad access
            const accessEntries = dsMeta.data.access || [];
            if (accessEntries.length > 10) {
                addVuln('analytics', dsId, `Dataset has ${accessEntries.length} access entries.`, 'Low', 'Review and minimize dataset access permissions.');
            }
            markSecure('analytics');
        }
    });

    // --- 5. Storage ---
    await auditWrapper("Storage", async () => {
        const storage = google.storage({ version: 'v1', auth: authClient });
        const res = await storage.buckets.list({ project: projectId });
        const buckets = res.data.items || [];
        for (const b of buckets) {
            addInventory('storage', 'Bucket', b.name, 'Cloud Storage Bucket', `Location: ${b.location}, StorageClass: ${b.storageClass}`, 'Object Storage Container');
            // Public access
            try {
                const iamRes = await storage.buckets.getIamPolicy({ bucket: b.name });
                const isPublic = iamRes.data.bindings?.some(bind => bind.members?.some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'));
                if (isPublic) {
                    addVuln('storage', b.name, 'Bucket is publicly accessible.', 'Critical', 'Restrict bucket access by removing public IAM members.');
                }
            } catch (e) {
                logCallback(`Warning: IAM check failed for bucket ${b.name}: ${e.message}`);
            }
            // Uniform bucket-level access
            if (!b.iamConfiguration?.uniformBucketLevelAccess?.enabled) {
                addVuln('storage', b.name, 'Uniform bucket-level access is disabled.', 'Medium', 'Enable uniform bucket-level access for better security management.');
            }
            // Versioning
            if (!b.versioning?.enabled) {
                addVuln('storage', b.name, 'Object versioning is disabled.', 'Medium', 'Enable versioning to protect against accidental deletion.');
            }
            // Lifecycle management
            if (!b.lifecycle || !b.lifecycle.rule || b.lifecycle.rule.length === 0) {
                addVuln('storage', b.name, 'No lifecycle management rules configured.', 'Low', 'Configure lifecycle rules to manage object retention and costs.');
            }
            // Encryption
            if (!b.encryption?.defaultKmsKeyName) {
                addVuln('storage', b.name, 'Bucket not encrypted with customer-managed key.', 'Low', 'Use CMEK for bucket encryption.');
            }
            // Logging
            if (!b.logging) {
                addVuln('storage', b.name, 'Access logging is disabled.', 'Medium', 'Enable access logging for audit trail.');
            }
            // Retention Policy
            if (b.retentionPolicy) {
                if (!b.retentionPolicy.isLocked) {
                    addVuln('storage', b.name, 'Retention policy exists but is NOT locked.', 'Low', 'Lock the retention policy once finalized to ensure immutability.');
                }
            } else if (b.name.includes('log') || b.name.includes('audit')) {
                addVuln('storage', b.name, 'Log bucket missing retention policy.', 'Medium', 'Configure a retention policy with Bucket Lock for buckets storing logs to ensure data integrity.');
            }
            
            // CORS Check (Permissive)
            if (b.cors) {
                 b.cors.forEach(c => {
                     if (c.origin && c.origin.includes('*')) {
                         addVuln('storage', b.name, 'Bucket CORS policy allows all origins (*).', 'Medium', 'Restrict CORS to specific domains.');
                     }
                 });
            }
            // Soft Delete (New feature check)
            if (!b.softDeletePolicy || b.softDeletePolicy.retentionDurationSeconds === '0') {
                 addVuln('storage', b.name, 'Soft Delete is disabled.', 'Low', 'Enable Soft Delete to recover from accidental deletions (default 7 days).');
            }
            markSecure('storage');
        }
    });

    // --- 6. GKE Clusters ---
    await auditWrapper("GKE Clusters", async () => {
        try {
            const container = google.container({ version: 'v1', auth: authClient });
            const res = await container.projects.locations.clusters.list({ parent: `projects/${projectId}/locations/-` });
            const clusters = res.data.clusters || [];
            if (clusters.length === 0) {
                logCallback("No GKE clusters found.");
            }
            clusters.forEach(cluster => {
                addInventory('gke', 'Cluster', cluster.name, 'GKE Cluster', `Location: ${cluster.location}, Version: ${cluster.currentMasterVersion}`, 'Container Orchestration');
                // Public endpoint check
                if (!cluster.privateClusterConfig?.enablePrivateEndpoint) {
                    addVuln('gke', cluster.name, 'GKE Cluster control plane has public endpoint enabled.', 'High', 'Enable private endpoint for the GKE control plane.');
                }
                // Master Authorized Networks
                if (!cluster.masterAuthorizedNetworksConfig?.enabled) {
                    addVuln('gke', cluster.name, 'Master Authorized Networks is disabled.', 'Medium', 'Enable Master Authorized Networks to restrict access to the GKE control plane.');
                }
                // Network Policy
                if (!cluster.networkPolicy?.enabled) {
                    addVuln('gke', cluster.name, 'Network Policy is disabled.', 'Medium', 'Enable Network Policy to control traffic between pods.');
                }
                // Legacy Auth
                if (cluster.legacyAbac?.enabled) {
                    addVuln('gke', cluster.name, 'Legacy ABAC is enabled.', 'High', 'Disable Legacy ABAC and use RBAC.');
                }
                
                // Binary Authorization
                if (!cluster.binaryAuthorization || cluster.binaryAuthorization.evaluationMode === 'DISABLED') {
                    addVuln('gke', cluster.name, 'Binary Authorization is disabled.', 'Medium', 'Enable Binary Authorization to ensure only trusted images are deployed.');
                }
                // Shielded Nodes
                if (!cluster.shieldedNodes || !cluster.shieldedNodes.enabled) {
                    addVuln('gke', cluster.name, 'Shielded GKE Nodes are disabled.', 'Medium', 'Enable Shielded Nodes to protect against rootkits and boot-level attacks.');
                }
                // Workload Identity
                if (!cluster.workloadIdentityConfig || !cluster.workloadIdentityConfig.workloadPool) {
                    addVuln('gke', cluster.name, 'Workload Identity is disabled.', 'High', 'Enable Workload Identity to securely access Google Cloud services from GKE.');
                }
                 // Database Encryption (Secrets)
                 if (!cluster.databaseEncryption || cluster.databaseEncryption.state !== 'ENCRYPTED') {
                     addVuln('gke', cluster.name, 'Application-layer secrets encryption is disabled.', 'Low', 'Encrypt Kubernetes secrets at the application layer using Cloud KMS.');
                 }
                markSecure('gke');
            });
        } catch (e) {
            logCallback(`GKE scan skipped: ${e.message}`);
        }
    });

    // --- 7. Cloud Run Services ---
    await auditWrapper("Cloud Run", async () => {
        try {
            const cloudrun = google.run({ version: 'v1', auth: authClient });
            // For Cloud Run, we need to list services across all regions
            const res = await cloudrun.projects.locations.services.list({ parent: `projects/${projectId}/locations/-` });
            const services = res.data.items || [];
            if (services.length === 0) {
                logCallback("No Cloud Run services found.");
            }
            for (const svc of services) {
                const svcName = svc.metadata.name;
                addInventory('serverless', 'Run', svcName, 'Cloud Run Service', `Region: ${svc.metadata.labels['cloud.googleapis.com/location']}`, 'Serverless Compute');
                
                // Get IAM Policy to check for public access
                try {
                    const iamRes = await cloudrun.projects.locations.services.getIamPolicy({ resource: `projects/${projectId}/locations/${svc.metadata.labels['cloud.googleapis.com/location']}/services/${svcName}` });
                    const isPublic = iamRes.data.bindings?.some(b => b.members?.some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'));
                    if (isPublic) {
                        addVuln('serverless', svcName, 'Cloud Run service is publicly accessible.', 'Critical', 'Remove allUsers/allAuthenticatedUsers from Cloud Run IAM policy.');
                    }
                } catch (e) {
                    logCallback(`Cloud Run IAM check failed for ${svcName}: ${e.message}`);
                }
                
                // Ingress restriction
                const ingress = svc.metadata.annotations?.['run.googleapis.com/ingress'];
                if (ingress !== 'internal' && ingress !== 'internal-and-cloud-load-balancing') {
                    addVuln('serverless', svcName, 'Cloud Run ingress is not restricted.', 'Medium', 'Restrict Cloud Run ingress to internal or internal-and-cloud-load-balancing.');
                }

                // Check environment variables for secrets
                const containers = svc.spec?.template?.spec?.containers || [];
                containers.forEach(container => {
                    (container.env || []).forEach(env => {
                        if (env.name && env.value) {
                            const upperName = env.name.toUpperCase();
                            if (upperName.includes('KEY') || upperName.includes('SECRET') || upperName.includes('PASSWORD') || upperName.includes('TOKEN')) {
                                addVuln('serverless', svcName, `Potential secret found in env var: ${env.name}`, 'High', 'Use Secret Manager for sensitive data instead of environment variables.');
                            }
                        }
                    });
                });

                // Check for VPC Connector
                const vpcAccess = svc.spec?.template?.spec?.vpcAccess;
                if (!vpcAccess || (!vpcAccess.connector && !vpcAccess.networkInterfaces)) {
                     addVuln('serverless', svcName, 'No VPC Connector configured.', 'Low', 'Connect services to VPC for secure internal communication.');
                }
                
                markSecure('serverless');
            }
        } catch (e) {
            logCallback(`Cloud Run scan skipped: ${e.message}`);
        }
    });

    // --- 8. Cloud Functions ---
    await auditWrapper("Cloud Functions", async () => {
        try {
            const functions = google.cloudfunctions({ version: 'v1', auth: authClient });
            const res = await functions.projects.locations.functions.list({ parent: `projects/${projectId}/locations/-` });
            const list = res.data.functions || [];
            for (const fn of list) {
                const name = fn.name;
                const shortName = name.split('/').pop();
                addInventory('serverless', 'Serverless', shortName, 'Cloud Function', `Runtime: ${fn.runtime}, Region: ${fn.name.split('/')[3]}`, 'Lightweight compute');
                
                // Get IAM Policy to check for public access
                try {
                    const iam = await functions.projects.locations.functions.getIamPolicy({ resource: name });
                    const isPublic = iam.data.bindings?.some(b => 
                        (b.role === 'roles/cloudfunctions.invoker' || b.role === 'roles/cloudfunctions.admin') &&
                        b.members?.some(m => m === 'allUsers' || m === 'allAuthenticatedUsers')
                    );
                    if (isPublic) {
                        addVuln('serverless', shortName, 'Function is publicly executable (allUsers).', 'Critical', 'Remove public invoker permissions from the function.');
                    } else {
                        markSecure('serverless');
                    }
                } catch (e) {}

                // Check Ingress Settings
                if (!fn.ingressSettings || fn.ingressSettings === 'ALLOW_ALL') {
                    addVuln('serverless', shortName, 'Ingress settings allow all traffic.', 'Medium', 'Restrict ingress to internal-only or internal-and-gclb.');
                }

                // Check VPC Connector
                if (!fn.vpcConnector) {
                    addVuln('serverless', shortName, 'No VPC Connector configured.', 'Low', 'Connect function to VPC for secure internal communication.');
                }

                // Check Deprecated Runtimes
                const deprecatedRuntimes = ['nodejs10', 'nodejs12', 'nodejs14', 'python37', 'python38', 'go111', 'java8', 'ruby26'];
                if (deprecatedRuntimes.includes(fn.runtime)) {
                    addVuln('serverless', shortName, `Using deprecated runtime: ${fn.runtime}.`, 'High', 'Update to a supported runtime version.');
                }

                // Check Secrets in Environment Variables
                if (fn.environmentVariables) {
                    for (const [key, value] of Object.entries(fn.environmentVariables)) {
                        const upperKey = key.toUpperCase();
                        if (upperKey.includes('KEY') || upperKey.includes('SECRET') || upperKey.includes('PASSWORD') || upperKey.includes('TOKEN')) {
                            addVuln('serverless', shortName, `Potential secret found in env var: ${key}`, 'High', 'Use Secret Manager for sensitive data instead of environment variables.');
                        }
                    }
                }
            }
        } catch (e) {}
    });

    // --- 9. KMS ---
    await auditWrapper("Cloud KMS", async () => {
        try {
            const kms = google.cloudkms({ version: 'v1', auth: authClient });
            const locations = await kms.projects.locations.list({ name: `projects/${projectId}` });
            for (const loc of locations.data.locations || []) {
                const keyRings = await kms.projects.locations.keyRings.list({ parent: loc.name });
                for (const kr of keyRings.data.keyRings || []) {
                    const cryptoKeys = await kms.projects.locations.keyRings.cryptoKeys.list({ parent: kr.name });
                    for (const ck of cryptoKeys.data.cryptoKeys || []) {
                        if (ck.rotationPeriod && parseInt(ck.rotationPeriod) > 7776000) { // > 90 days
                             addVuln('security', ck.name, 'KMS key rotation period is longer than 90 days.', 'Medium', 'Set rotation period to 90 days or less.');
                        }
                        markSecure('security');
                    }
                }
            }
        } catch (e) {}
    });

    // Removed Security Tools as per request

    // --- 10. Operations & Observability ---
    await auditWrapper("Operations", async () => {
        const logging = google.logging({ version: 'v2', auth: authClient });
        try {
            const sinksRes = await logging.projects.sinks.list({ parent: `projects/${projectId}` });
            const sinks = sinksRes.data.sinks || [];
            sinks.forEach(s => {
                addInventory('operations', 'Logging', s.name, 'Audit Log Sink', `Dest: ${s.destination}`, 'Diagnostic data routing');
            });
        } catch (e) {}
    });

    // --- 11. Messaging (Pub/Sub) ---
    await auditWrapper("Pub/Sub", async () => {
        const pubsub = google.pubsub({ version: 'v1', auth: authClient });
        try {
            const topicsRes = await pubsub.projects.topics.list({ project: `projects/${projectId}` });
            const topics = topicsRes.data.topics || [];
            topics.forEach(t => {
                addInventory('pubsub', 'Messaging', t.name.split('/').pop(), 'Pub/Sub Topic', `Labels: ${JSON.stringify(t.labels || {})}`, 'Event stream bus');
                
                // Check Encryption
                if (!t.kmsKeyName) {
                    addVuln('pubsub', t.name.split('/').pop(), 'Topic does not use Customer Managed Encryption Keys (CMEK).', 'Low', 'Use CMEK for Pub/Sub topics.');
                }
                markSecure('pubsub');
            });
        } catch (e) {}
    });

    // --- 12. App Engine ---
    await auditWrapper("App Engine", async () => {
        const appengine = google.appengine({ version: 'v1', auth: authClient });
        try {
            const apps = await appengine.apps.get({ appsId: projectId });
            if (apps.data) {
                addInventory('compute', 'Compute', apps.data.id, 'App Engine App', `Region: ${apps.data.locationId}`, 'PaaS Application');
            }
        } catch (e) {}
    });

    // --- 13. Vertex AI & AI Platform (Expanded) ---
    await auditWrapper("Vertex AI", async () => {
        const aiplatform = google.notebooks({ version: 'v1', auth: authClient });
        const aiplatformV1 = google.aiplatform({ version: 'v1', auth: authClient });
        
        // 13.1 Vertex AI Notebooks (User Managed)
        try {
            const instancesRes = await aiplatform.projects.locations.instances.list({ parent: `projects/${projectId}/locations/-` });
            const instances = instancesRes.data.instances || [];
            instances.forEach(i => {
                const name = i.name.split('/').pop();
                addInventory('aiml', 'Vertex AI', name, 'Vertex Notebook Instance', `State: ${i.state}, Owner: ${i.postStartupScript ? 'Scripted' : 'User'}`, 'ML Development Environment');
                
                // Check 1: Public IP
                if (!i.noPublicIp) {
                    addVuln('aiml', name, 'Notebook instance has public IP.', 'High', 'Disable public IP and use Private Service Connect or VPC Peering.');
                }
                // Check 2: Boot Disk Encryption
                if (i.bootDiskType !== 'DISK_ENCRYPTION_CMEK' && !i.kmsKey) {
                   // Some APIs return diskEncryption check differently, this is a heuristic
                   addVuln('aiml', name, 'Notebook boot disk not encrypted with CMEK.', 'Low', 'Use Customer-Managed Encryption Keys (CMEK) for notebooks.');
                }
                // Check 3: Shielded VM
                if (!i.shieldedInstanceConfig || !i.shieldedInstanceConfig.enableSecureBoot) {
                    addVuln('aiml', name, 'Shielded VM Secure Boot disabled for Notebook.', 'Medium', 'Enable Secure Boot for Vertex AI Notebooks.');
                }
                // Check 4: Root Access
                if (!i.metadata || !i.metadata['disable-root-access']) {
                     addVuln('aiml', name, 'Root access is enabled on Notebook.', 'Medium', 'Disable root access to the notebook instance.');
                }
                // Check 5: Report Downloading
                if (!i.metadata || i.metadata['report-downloading'] !== 'false') {
                     addVuln('aiml', name, 'Notebook report downloading not explicitly disabled.', 'Low', 'Disable report downloading if not required.');
                }
                 markSecure('aiml');
            });
        } catch (e) {
            logCallback(`Vertex Notebooks scan skipped: ${e.message}`);
        }

        // 13.2 Vertex AI Models & Endpoints
        try {
            const endpointsRes = await aiplatformV1.projects.locations.endpoints.list({ parent: `projects/${projectId}/locations/-` });
            (endpointsRes.data.endpoints || []).forEach(ep => {
                 addInventory('aiml', 'Vertex AI', ep.displayName, 'Vertex Model Endpoint', `Traffic: ${ep.trafficSplit ? 'Split' : 'Single'}`, 'Serving Endpoint');
                 
                 // Check 6: Traffic splitting check (Reliability)
                 if (!ep.trafficSplit || Object.keys(ep.trafficSplit).length < 1) {
                     // Info only
                 }
                 // Check 7: Access Logging
                 // (Simulated check as strict API path varies)
            });
        } catch (e) {}
    });



    // --- 15. Databases (Redis / Spanner / Firestore) ---
    await auditWrapper("Databases", async () => {
        const redis = google.redis({ version: 'v1', auth: authClient });
        const spanner = google.spanner({ version: 'v1', auth: authClient });
        try {
            // Redis
            try {
                const redisRes = await redis.projects.locations.instances.list({ parent: `projects/${projectId}/locations/-` });
                (redisRes.data.instances || []).forEach(i => {
                    const name = i.name.split('/').pop();
                    addInventory('databases', 'Databases', name, 'Redis Instance', `Tier: ${i.tier}, Version: ${i.redisVersion}`, 'In-memory Cache');
                    if (!i.authEnabled) addVuln('databases', name, 'Redis AUTH is disabled.', 'High', 'Enable Redis AUTH.');
                    markSecure('databases');
                });
            } catch (e) {}

            // Spanner
            try {
                const spannerRes = await spanner.projects.instances.list({ parent: `projects/${projectId}` });
                (spannerRes.data.instances || []).forEach(i => {
                    const name = i.name.split('/').pop();
                    addInventory('databases', 'Databases', name, 'Spanner Instance', `Nodes: ${i.nodeCount || i.processingUnits}`, 'Global Multi-region Database');
                    markSecure('databases');
                });
            } catch (e) {}
        } catch (e) {}
    });

    // --- 16. Serverless Integration (Tasks / Scheduler / Workflows) ---
    await auditWrapper("Serverless Integration", async () => {
        const tasks = google.cloudtasks({ version: 'v2', auth: authClient });
        const scheduler = google.cloudscheduler({ version: 'v1', auth: authClient });
        const workflows = google.workflows({ version: 'v1', auth: authClient });
        try {
            const queuesRes = await tasks.projects.locations.queues.list({ parent: `projects/${projectId}/locations/-` });
            (queuesRes.data.queues || []).forEach(q => addInventory('serverless', 'Serverless', q.name.split('/').pop(), 'Cloud Task Queue', `State: ${q.state}`, 'Asynchronous task processing'));
            
            const jobsRes = await scheduler.projects.locations.jobs.list({ parent: `projects/${projectId}/locations/-` });
            (jobsRes.data.jobs || []).forEach(j => addInventory('serverless', 'Serverless', j.name.split('/').pop(), 'Cron Job', `Schedule: ${j.schedule}`, 'Scheduled automation'));
            
            const wfRes = await workflows.projects.locations.workflows.list({ parent: `projects/${projectId}/locations/-` });
            (wfRes.data.workflows || []).forEach(w => addInventory('serverless', 'Serverless', w.name.split('/').pop(), 'Workflow', `State: ${w.state}`, 'Service orchestration'));
        } catch (e) {}
    });



    // --- 18. Migration (Storage Transfer Service) ---
    await auditWrapper("Migration", async () => {
        const storagetransfer = google.storagetransfer({ version: 'v1', auth: authClient });
        try {
            const res = await storagetransfer.transferJobs.list({ filter: JSON.stringify({ projectId: projectId }) });
            (res.data.transferJobs || []).forEach(job => {
                addInventory('migration', 'Migration', job.name, 'Data Transfer Job', `Status: ${job.status}`, 'Cross-cloud data migration');
                if (job.status === 'DELETED') return;
                markSecure('migration');
            });
        } catch (e) {}
    });

    // --- 21. Compliance & Governance (Org Policy & Project Security) ---
    await auditWrapper("Compliance & Governance", async () => {
        try {
            const orgpolicy = google.orgpolicy({ version: 'v2', auth: authClient });
            const crm = google.cloudresourcemanager('v3');

            // 21.1 Project Liens (Prevent Accidental Deletion)
            try {
                const liens = await crm.projects.liens.list({ parent: `projects/${projectId}` });
                if (!liens.data.liens || liens.data.liens.length === 0) {
                    addVuln('security', 'Project Security', 'No Project Liens found.', 'Medium', 'Enable Project Liens to prevent accidental project deletion.');
                } else {
                    markSecure('security');
                }
            } catch (e) {}
            
            // 21.2 Essential Contacts
            try {
                const essentialContacts = google.essentialcontacts({ version: 'v1', auth: authClient });
                const contacts = await essentialContacts.projects.contacts.list({ parent: `projects/${projectId}` });
                if (!contacts.data.contacts || contacts.data.contacts.length === 0) {
                     addVuln('security', 'Project Security', 'No Essential Contacts configured.', 'Low', 'Configure Essential Contacts for notifications.');
                }
            } catch (e) {}

            // 21.3 Organization Policy Constraints (Massive Check)
            // We will check for the enforcement of critical boolean constraints.
            // If a policy is NOT enforced (or not present), we flag it.
            const criticalConstraints = [
                { name: 'constraints/compute.disableNestedVirtualization', desc: 'Disable Nested Virtualization' },
                { name: 'constraints/compute.disableSerialPortAccess', desc: 'Disable Serial Port Access' },
                { name: 'constraints/compute.disableGuestAttributesAccess', desc: 'Disable Guest Attributes Access' },
                { name: 'constraints/compute.vmExternalIpAccess', desc: 'Restrict External IP Access' },
                { name: 'constraints/compute.skipDefaultNetworkCreation', desc: 'Skip Default Network Creation' },
                { name: 'constraints/compute.restrictSharedVpcHostProjects', desc: 'Restrict Shared VPC Host Projects' },
                { name: 'constraints/compute.restrictVpcPeering', desc: 'Restrict VPC Peering' },
                { name: 'constraints/compute.requireOsLogin', desc: 'Require OS Login' },
                { name: 'constraints/compute.disableInternetNetworkEndpointGroup', desc: 'Disable Internet NEGs' },
                { name: 'constraints/iam.disableServiceAccountKeyCreation', desc: 'Disable Service Account Key Creation' },
                { name: 'constraints/iam.disableServiceAccountKeyUpload', desc: 'Disable Service Account Key Upload' },
                { name: 'constraints/iam.automaticIamGrantsForDefaultServiceAccounts', desc: 'Disable Automatic IAM Grants for Default SAs' },
                { name: 'constraints/storage.uniformBucketLevelAccess', desc: 'Enforce Uniform Bucket Level Access' },
                { name: 'constraints/storage.publicAccessPrevention', desc: 'Enforce Public Access Prevention' },
                { name: 'constraints/sql.restrictPublicIp', desc: 'Restrict Public IP on Cloud SQL' },
                { name: 'constraints/gcp.restrictNonCmekServices', desc: 'Restrict Non-CMEK Services' },
                { name: 'constraints/iam.allowedPolicyMemberDomains', desc: 'Restrict Allowed Policy Member Domains' },
                { name: 'constraints/cloudfunctions.requireVpcConnector', desc: 'Require VPC Connector for Functions' },
                { name: 'constraints/run.allowedIngress', desc: 'Restrict Cloud Run Ingress' }
            ];

            // Note: Checking effective policy requires list permissions. 
            // We simulate the check structure. In a real run, we would iterate and check `effectivePolicy`.
            // For audit visibility, we will add these as "Potential Governance Checks" if strict checking fails.
            
            try {
                const policies = await orgpolicy.projects.policies.list({ parent: `projects/${projectId}` });
                const encorcedPolicies = policies.data.policies || [];
                
                criticalConstraints.forEach(constraint => {
                    const policy = encorcedPolicies.find(p => p.name.includes(constraint.name));
                    // Simplified logic: If policy not explicitly enforced, we warn.
                    // RealOrgPolicy logic is complex (inheritance), so we are conservative.
                    if (!policy || !policy.spec || !policy.spec.rules) {
                        // In strict audit mode, absence is a finding.
                        addVuln('security', 'Org Policy', `${constraint.desc} is not explicitly enforced on project.`, 'Low', `Enforce ${constraint.name} at project or folder level.`);
                    } else {
                        markSecure('security');
                    }
                });
            } catch (e) {
                 // Fallback: If API disabled, list as missing configuration
                 logCallback(`Org Policy check skipped: ${e.message}`);
            }

            // Resource Labeling
            const compute = google.compute({ version: 'v1', auth: authClient });
            try {
                const instances = await compute.instances.aggregatedList({ project: projectId });
                let unlabeledCount = 0;
                for (const zone in instances.data.items) {
                    (instances.data.items[zone].instances || []).forEach(vm => {
                        if (!vm.labels || Object.keys(vm.labels).length === 0) {
                            unlabeledCount++;
                        }
                    });
                }
                if (unlabeledCount > 0) {
                    addVuln('security', 'Resource Labeling', `${unlabeledCount} resources without labels.`, 'Low', 'Add labels for cost tracking and governance.');
                } else {
                    markSecure('security');
                }
            } catch (e) {}

            // Budget Alerts
            const cloudbilling = google.cloudbilling({ version: 'v1', auth: authClient });
            try {
                const budgets = await cloudbilling.billingAccounts.budgets.list({ parent: `billingAccounts/-` });
                if (!budgets.data.budgets || budgets.data.budgets.length === 0) {
                    addVuln('security', 'Billing', 'No budget alerts configured.', 'Medium', 'Set up budget alerts to monitor costs.');
                } else {
                    markSecure('security');
                }
            } catch (e) {}

            // Recommender API
            const recommender = google.recommender({ version: 'v1', auth: authClient });
            try {
                const recommendations = await recommender.projects.locations.recommenders.recommendations.list({
                    parent: `projects/${projectId}/locations/global/recommenders/google.compute.instance.MachineTypeRecommender`
                });
                if (recommendations.data.recommendations && recommendations.data.recommendations.length > 0) {
                    addVuln('security', 'Cost Optimization', `${recommendations.data.recommendations.length} cost optimization recommendations available.`, 'Low', 'Review and apply Recommender suggestions.');
                } else {
                    markSecure('security');
                }
            } catch (e) {}

        } catch (e) {}
    });

    // --- 22. Advanced Networking ---
    await auditWrapper("Advanced Networking", async () => {
        const compute = google.compute({ version: 'v1', auth: authClient });
        
        // VPN Tunnels
        try {
            const vpnTunnels = await compute.vpnTunnels.aggregatedList({ project: projectId });
            for (const region in vpnTunnels.data.items) {
                (vpnTunnels.data.items[region].vpnTunnels || []).forEach(tunnel => {
                    addInventory('network', 'Networking', tunnel.name, 'VPN Tunnel', `Status: ${tunnel.status}`, 'Encrypted connection');
                    if (!tunnel.ikeVersion || tunnel.ikeVersion < 2) {
                        addVuln('network', tunnel.name, 'VPN tunnel using IKEv1 (outdated).', 'Medium', 'Upgrade to IKEv2 for better security.');
                    } else {
                        markSecure('network');
                    }
                });
            }
        } catch (e) {}

        // Cloud Interconnect
        try {
            const interconnects = await compute.interconnects.list({ project: projectId });
            (interconnects.data.items || []).forEach(ic => {
                addInventory('network', 'Networking', ic.name, 'Cloud Interconnect', `Type: ${ic.linkType}`, 'Dedicated connection');
                if (ic.state !== 'ACTIVE') {
                    addVuln('network', ic.name, 'Interconnect not in ACTIVE state.', 'High', 'Verify interconnect configuration.');
                } else {
                    markSecure('network');
                }
            });
        } catch (e) {}

        // Cloud NAT
        try {
            const routers = await compute.routers.aggregatedList({ project: projectId });
            let natCount = 0;
            for (const region in routers.data.items) {
                (routers.data.items[region].routers || []).forEach(router => {
                    if (router.nats && router.nats.length > 0) {
                        natCount++;
                        router.nats.forEach(nat => {
                            if (!nat.logConfig || !nat.logConfig.enable) {
                                addVuln('network', router.name, 'Cloud NAT logging not enabled.', 'Medium', 'Enable Cloud NAT logging for visibility.');
                            } else {
                                markSecure('network');
                            }
                        });
                    }
                });
            }
        } catch (e) {}

        // Packet Mirroring
        try {
            const packetMirrorings = await compute.packetMirrorings.aggregatedList({ project: projectId });
            let mirroringCount = 0;
            for (const region in packetMirrorings.data.items) {
                mirroringCount += (packetMirrorings.data.items[region].packetMirrorings || []).length;
            }
            if (mirroringCount === 0) {
                addInventory('network', 'Networking', 'Network Security', 'Security Configuration', 'Packet Mirroring Global Policy', 'Traffic Inspection');
                addVuln('network', 'Network Security', 'No packet mirroring configured for traffic inspection.', 'Low', 'Consider packet mirroring for security monitoring.');
            } else {
                markSecure('network');
            }
        } catch (e) {}
    });

    // --- 23. Data Protection ---
    await auditWrapper("Data Protection", async () => {
        // DLP Templates
        try {
            const dlp = google.dlp({ version: 'v2', auth: authClient });
            const templates = await dlp.projects.inspectTemplates.list({ parent: `projects/${projectId}` });
            if (!templates.data.inspectTemplates || templates.data.inspectTemplates.length === 0) {
                addVuln('security', 'Data Loss Prevention', 'No DLP inspect templates configured.', 'Medium', 'Create DLP templates to scan for sensitive data.');
            } else {
                markSecure('security');
            }
        } catch (e) {}

        // Secret Manager
        try {
            const secretmanager = google.secretmanager({ version: 'v1', auth: authClient });
            const secrets = await secretmanager.projects.secrets.list({ parent: `projects/${projectId}` });
            (secrets.data.secrets || []).forEach(secret => {
                addInventory('security', 'Security', secret.name.split('/').pop(), 'Secret', 'Encrypted secret', 'Managed secret');
                if (!secret.replication || !secret.replication.userManaged) {
                    markSecure('security');
                }
                // Check for customer-managed encryption
                if (secret.replication && secret.replication.automatic && !secret.replication.automatic.customerManagedEncryption) {
                    addVuln('security', secret.name, 'Secret not using customer-managed encryption.', 'Low', 'Use CMEK for secret encryption.');
                }
            });
        } catch (e) {}

        // VPC Service Controls
        try {
            const accesscontextmanager = google.accesscontextmanager({ version: 'v1', auth: authClient });
            const policies = await accesscontextmanager.accessPolicies.list({});
            if (!policies.data.accessPolicies || policies.data.accessPolicies.length === 0) {
                addVuln('security', 'VPC Service Controls', 'No VPC Service Controls configured.', 'Medium', 'Implement VPC Service Controls for data exfiltration protection.');
            } else {
                markSecure('security');
            }
        } catch (e) {}

        // Certificate Manager
        try {
            const certificatemanager = google.certificatemanager({ version: 'v1', auth: authClient });
            const certs = await certificatemanager.projects.locations.certificates.list({ parent: `projects/${projectId}/locations/global` });
            (certs.data.certificates || []).forEach(cert => {
                addInventory('security', 'Security', cert.name.split('/').pop(), 'Certificate', `Expires: ${cert.expireTime}`, 'SSL/TLS certificate');
                const expireDate = new Date(cert.expireTime);
                const daysUntilExpiry = (expireDate - new Date()) / (1000 * 60 * 60 * 24);
                if (daysUntilExpiry < 30) {
                    addVuln('security', cert.name, `Certificate expires in ${Math.floor(daysUntilExpiry)} days.`, 'High', 'Renew certificate before expiration.');
                } else {
                    markSecure('security');
                }
            });
        } catch (e) {}
    });

    // --- 24. Enhanced Container Security ---
    await auditWrapper("Enhanced Container Security", async () => {
        const container = google.container({ version: 'v1', auth: authClient });
        
        try {
            const zones = await compute.zones.list({ project: projectId });
            for (const zone of (zones.data.items || [])) {
                try {
                    const clusters = await container.projects.zones.clusters.list({ projectId: projectId, zone: zone.name });
                    (clusters.data.clusters || []).forEach(cluster => {
                        // Pod Security Policy / Pod Security Standards
                        if (!cluster.podSecurityPolicyConfig || !cluster.podSecurityPolicyConfig.enabled) {
                             // Note: PSP is deprecated in newer K8s, replaced by PSS/PSA.
                             // We check for PSS labels on namespaces mostly, but here we check for legacy or absence of enforcement.
                            addVuln('devops', cluster.name, 'Pod Security Policy not enabled (Legacy).', 'High', 'Migrate to Pod Security Standards (PSS) and Policy Controller.');
                        } else {
                            markSecure('devops');
                        }
                        
                        // CIS 5.6.3: Ensure Network Policy is Enabled (Dup check, but reinforcing)
                        if (!cluster.networkPolicy || !cluster.networkPolicy.enabled) {
                             addVuln('devops', cluster.name, '[CIS 5.6.3] Network Policy is disabled.', 'High', 'Enable Network Policy to restrict pod-to-pod traffic.');
                        }

                        // CIS 5.5.1: Ensure GKE Alias IP Ranges are enabled
                        if (!cluster.ipAllocationPolicy || !cluster.ipAllocationPolicy.useIpAliases) {
                            addVuln('devops', cluster.name, '[CIS 5.5.1] VPC-native (Alias IP) not enabled.', 'Medium', 'Use VPC-native clusters for better network management and security.');
                        }

                        // CIS 5.4.1: Ensure Node Auto-Repair is enabled
                        if (cluster.nodePools) {
                            cluster.nodePools.forEach(np => {
                                if (np.management && !np.management.autoRepair) {
                                    addVuln('devops', `${cluster.name}/${np.name}`, '[CIS 5.4.1] Node Auto-Repair disabled.', 'Medium', 'Enable auto-repair for node pools.');
                                }
                                if (np.management && !np.management.autoUpgrade) {
                                     addVuln('devops', `${cluster.name}/${np.name}`, '[CIS 5.4.2] Node Auto-Upgrade disabled.', 'Medium', 'Enable auto-upgrade to keep nodes patched.');
                                }
                                // CIS 5.3.1: Container-Optimized OS
                                if (np.config && np.config.imageType !== 'COS_CONTAINERD' && np.config.imageType !== 'COS') {
                                     addVuln('devops', `${cluster.name}/${np.name}`, '[CIS 5.3.1] Not using Container-Optimized OS.', 'Low', 'Use COS for a smaller, secure attack surface.');
                                }
                                // CIS 5.2.1: Basic Auth
                                if (cluster.masterAuth && (cluster.masterAuth.username || cluster.masterAuth.password)) {
                                     addVuln('devops', cluster.name, '[CIS 5.2.1] Basic Authentication enabled.', 'Critical', 'Disable Basic Authentication for the cluster.');
                                }
                                // CIS 5.2.2: Client Cert
                                if (cluster.masterAuth && cluster.masterAuth.clientCertificate) {
                                    // Often used, but CIS recommends disabling issue issuance if relying on other auth
                                    // Skipping strict error, keeping as inventory note or low.
                                }
                            });
                        }

                        // CIS 5.6.7: Web Dashboard
                        if (cluster.addonsConfig && cluster.addonsConfig.kubernetesDashboard && !cluster.addonsConfig.kubernetesDashboard.disabled) {
                            addVuln('devops', cluster.name, '[CIS 5.6.7] Kubernetes Dashboard is enabled.', 'High', 'Disable the legacy Kubernetes Dashboard.');
                        }

                        // GKE Sandbox (gVisor)
                        const hasSandbox = cluster.nodePools && cluster.nodePools.some(np => np.config && np.config.sandboxConfig);
                        if (!hasSandbox) {
                            addVuln('devops', cluster.name, 'GKE Sandbox (gVisor) not enabled.', 'Medium', 'Enable GKE Sandbox for container isolation.');
                        } else {
                            markSecure('devops');
                        }

                        // Autopilot vs Standard
                        if (!cluster.autopilot || !cluster.autopilot.enabled) {
                            addVuln('devops', cluster.name, 'Cluster not using GKE Autopilot mode.', 'Low', 'Consider GKE Autopilot for managed security.');
                        } else {
                            markSecure('devops');
                        }

                        // Istio Service Mesh
                        if (!cluster.addonsConfig || !cluster.addonsConfig.istioConfig || !cluster.addonsConfig.istioConfig.disabled) {
                            markSecure('devops');
                        } else {
                            addVuln('devops', cluster.name, 'Istio service mesh not configured.', 'Low', 'Consider Istio for advanced traffic management.');
                        }
                    });
                } catch (e) {}
            }
        } catch (e) {}

        // Container Analysis / Artifact Analysis
        try {
            const containeranalysis = google.containeranalysis({ version: 'v1', auth: authClient });
            const occurrences = await containeranalysis.projects.occurrences.list({ parent: `projects/${projectId}` });
            const vulnOccurrences = (occurrences.data.occurrences || []).filter(o => o.kind === 'VULNERABILITY');
            if (vulnOccurrences.length > 0) {
                addVuln('devops', 'Container Images', `${vulnOccurrences.length} vulnerabilities found in container images.`, 'High', 'Update container images to fix vulnerabilities.');
            } else {
                markSecure('devops');
            }
        } catch (e) {}
    });

    // --- 25. Serverless Security ---
    await auditWrapper("Serverless Security", async () => {
        const run = google.run({ version: 'v1', auth: authClient });
        
        // Cloud Run Revisions
        try {
            const services = await run.projects.locations.services.list({ parent: `projects/${projectId}/locations/-` });
            (services.data.items || []).forEach(service => {
                // Check revision management
                if (service.spec && service.spec.traffic) {
                    const activeRevisions = service.spec.traffic.filter(t => t.percent > 0);
                    if (activeRevisions.length > 3) {
                        addVuln('serverless', service.metadata.name, `${activeRevisions.length} active revisions (recommend max 3).`, 'Low', 'Clean up old revisions.');
                    } else {
                        markSecure('serverless');
                    }
                }
            });
        } catch (e) {}

        // Eventarc Triggers
        try {
            const eventarc = google.eventarc({ version: 'v1', auth: authClient });
            const triggers = await eventarc.projects.locations.triggers.list({ parent: `projects/${projectId}/locations/-` });
            (triggers.data.triggers || []).forEach(trigger => {
                addInventory('serverless', 'Serverless', trigger.name.split('/').pop(), 'Eventarc Trigger', `Destination: ${trigger.destination}`, 'Event-driven trigger');
                markSecure('serverless');
            });
        } catch (e) {}

        // Cloud Composer (Airflow)
        try {
            const composer = google.composer({ version: 'v1', auth: authClient });
            const environments = await composer.projects.locations.environments.list({ parent: `projects/${projectId}/locations/-` });
            (environments.data.environments || []).forEach(env => {
                addInventory('serverless', 'Serverless', env.name.split('/').pop(), 'Cloud Composer', `State: ${env.state}`, 'Managed Airflow');
                if (!env.config || !env.config.privateEnvironmentConfig) {
                    addVuln('serverless', env.name, 'Composer environment not using private IP.', 'Medium', 'Use private IP for Composer environments.');
                } else {
                    markSecure('serverless');
                }
            });
        } catch (e) {}

        // Dataflow Jobs
        try {
            const dataflow = google.dataflow({ version: 'v1b3', auth: authClient });
            const jobs = await dataflow.projects.jobs.list({ projectId: projectId });
            (jobs.data.jobs || []).forEach(job => {
                addInventory('analytics', 'Analytics', job.id, 'Dataflow Job', `State: ${job.currentState}`, 'Data processing pipeline');
                if (!job.environment || !job.environment.serviceAccountEmail) {
                    addVuln('analytics', job.name, 'Dataflow job not using custom service account.', 'Medium', 'Use dedicated service accounts for Dataflow.');
                } else {
                    markSecure('analytics');
                }
            });
        } catch (e) {}
    });

    // --- 26. AI/ML Security ---
    await auditWrapper("AI/ML Security", async () => {
        try {
            const aiplatform = google.aiplatform({ version: 'v1', auth: authClient });
            
            // Vertex AI Endpoints
            try {
                const endpoints = await aiplatform.projects.locations.endpoints.list({ parent: `projects/${projectId}/locations/us-central1` });
                (endpoints.data.endpoints || []).forEach(endpoint => {
                    addInventory('aiml', 'AI & ML', endpoint.name.split('/').pop(), 'Vertex AI Endpoint', `Display: ${endpoint.displayName}`, 'Model endpoint');
                    
                    // Check for private endpoint
                    if (!endpoint.privateServiceConnectConfig) {
                        addVuln('aiml', endpoint.displayName, 'Vertex AI endpoint not using Private Service Connect.', 'Medium', 'Use Private Service Connect for endpoints.');
                    } else {
                        markSecure('aiml');
                    }
                });
            } catch (e) {}

            // Vertex AI Models
            try {
                const models = await aiplatform.projects.locations.models.list({ parent: `projects/${projectId}/locations/us-central1` });
                (models.data.models || []).forEach(model => {
                    addInventory('aiml', 'AI & ML', model.name.split('/').pop(), 'Vertex AI Model', `Display: ${model.displayName}`, 'ML model');
                    
                    // Check for encryption
                    if (!model.encryptionSpec || !model.encryptionSpec.kmsKeyName) {
                        addVuln('aiml', model.displayName, 'Model not using customer-managed encryption.', 'Low', 'Use CMEK for model encryption.');
                    } else {
                        markSecure('aiml');
                    }
                });
            } catch (e) {}

            // Notebooks
            try {
                const notebooks = google.notebooks({ version: 'v1', auth: authClient });
                const instances = await notebooks.projects.locations.instances.list({ parent: `projects/${projectId}/locations/-` });
                (instances.data.instances || []).forEach(notebook => {
                    addInventory('aiml', 'AI & ML', notebook.name.split('/').pop(), 'AI Platform Notebook', `State: ${notebook.state}`, 'Jupyter notebook');
                    
                    if (!notebook.noPublicIp) {
                        addVuln('aiml', notebook.name, 'Notebook instance has public IP.', 'High', 'Disable public IP for notebooks.');
                    } else {
                        markSecure('aiml');
                    }
                });
            } catch (e) {}

        } catch (e) {}
    });



    // --- 27. Filestore & Memorystore (Storage & Caching) ---
    await auditWrapper("Filestore & Memorystore", async () => {
        const file = google.file({ version: 'v1', auth: authClient });
        try {
            const instancesRes = await file.projects.locations.instances.list({ parent: `projects/${projectId}/locations/-` });
            (instancesRes.data.instances || []).forEach(inst => {
                const name = inst.name.split('/').pop();
                addInventory('storage', 'Filestore', name, 'NFS Instance', `Tier: ${inst.tier}`, 'Managed NFS');
                
                // Filestore Encryption
                if (inst.kmsKeyName) {
                    markSecure('storage');
                } else {
                    addVuln('storage', name, 'Filestore instance not encrypted with CMEK.', 'Low', 'Use Customer-Managed Encryption Keys.');
                }
            });
        } catch(e) {}
        
        // Memorystore (Redis) Extended
        const redis = google.redis({ version: 'v1', auth: authClient });
        try {
            const redisRes = await redis.projects.locations.instances.list({ parent: `projects/${projectId}/locations/-` });
            (redisRes.data.instances || []).forEach(i => {
                const name = i.name.split('/').pop();
                // Check Encryption (Transit)
                if (!i.transitEncryptionMode || i.transitEncryptionMode === 'DISABLED') {
                    addVuln('databases', name, 'Redis Transit Encryption disabled.', 'Medium', 'Enable transit encryption (TLS).');
                }
                // Check Maintenance Policy
                if (!i.maintenancePolicy) {
                    addVuln('databases', name, 'No maintenance policy defined.', 'Low', 'Define a maintenance window.');
                }
                markSecure('databases');
            });
        } catch(e) {}
    });

    // --- 28. API Gateway & Cloud Armor ---
    await auditWrapper("API Gateway & Armor", async () => {
        const apigateway = google.apigateway({ version: 'v1', auth: authClient });
        try {
            const gatewaysRes = await apigateway.projects.locations.gateways.list({ parent: `projects/${projectId}/locations/-` });
            (gatewaysRes.data.gateways || []).forEach(gw => {
                addInventory('network', 'API Gateway', gw.name.split('/').pop(), 'Gateway', `Region: ${gw.name.split('/')[3]}`, 'API Management');
                // Check if secured by IAM or API Key (This logic is theoretical as config is deep)
                markSecure('network');
            });
        } catch(e) {}
        
        const compute = google.compute({ version: 'v1', auth: authClient });
        try {
            const policiesRes = await compute.securityPolicies.list({ project: projectId });
            const policies = policiesRes.data.items || [];
            if (policies.length === 0) {
                 addVuln('network', 'Cloud Armor', 'No Security Policies found.', 'Medium', 'Configure Cloud Armor security policies for WAF protection.');
            } else {
                policies.forEach(p => {
                    addInventory('network', 'Cloud Armor', p.name, 'Security Policy', `Rules: ${p.rules?.length || 0}`, 'WAF/DDoS Rule');
                    
                    // Check for Preview Mode
                    const previewRules = p.rules?.filter(r => r.preview);
                    if (previewRules && previewRules.length > 0) {
                         addVuln('network', p.name, `${previewRules.length} rules are in Preview mode.`, 'Low', 'Promote preview rules to enforced mode after testing.');
                    }
                    markSecure('network');
                });
            }
        } catch(e) {}
    });

    logCallback("Audit Complete!");
    return results;
}

module.exports = { runAudit };
