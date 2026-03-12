const cron = require('node-cron');
const { sendSecurityReport } = require('./email_service');
// Note: We'll need to pass instances or require them carefully to avoid circular deps
// Let's assume we pass the audit functions when initializing the scheduler

class AuditScheduler {
    constructor(auditFunctions, resultHandlers) {
        this.auditFunctions = auditFunctions; // { gcp: runAudit, aws: runAWSAudit, azure: runSimulatedAudit }
        this.resultHandlers = resultHandlers; // { saveResults: saveScanResults, saveHistory: saveHistory, updateSchedule: updateSchedule }
        this.jobs = new Map(); // Store active active cron jobs
        
        // Heartbeat removed after verification.
        this.leadTimeMinutes = 0;
        console.log(`[SCHEDULER] Initialized with ${this.leadTimeMinutes}min lead time.`);
    }

    /**
     * scheduleScan
     * @param {string} userId - The user who owns the schedule
     * @param {Object} config - { platform, frequency: 'daily'|'weekly'|'monthly', email, credentials }
     */
    scheduleScan(userId, config) {
        console.log(`[SCHEDULER-DEBUG] Entering scheduleScan for ${userId}. Config:`, JSON.stringify(config));
        const { platform, frequency, email, credentials, startDate, endDate, id } = config;
        
        // Stop existing job for this specific schedule ID if any
        this.stopScan(userId, platform, id);

        let cronExpression;
        const [hour, minute] = (config.time || '09:00').split(':').map(Number);
        const leadTimeMinutes = this.leadTimeMinutes;

        // Calculate trigger time with lead offset
        let tMin = minute - leadTimeMinutes;
        let tHour = hour;
        let tDayShift = 0;

        if (tMin < 0) {
            tMin += 60;
            tHour -= 1;
        }
        if (tHour < 0) {
            tHour += 24;
            tDayShift = -1;
        }

        const dow = config.dayOfWeek !== undefined ? config.dayOfWeek : 1;
        const dom = config.dayOfMonth !== undefined ? config.dayOfMonth : 1;

        // Adjusted fields for cron
        let triggerDow = dow;
        let triggerDom = dom;
        let triggerDateString = config.date;

        if (tDayShift === -1) {
            triggerDow = (dow - 1 + 7) % 7;
            // For DOM, if it was 1, it's hard to specify "last day of month" cleanly in one cron exp without L.
            // Simplified: subtract 1. If it becomes 0, we'll just log a warning for now as it's an edge case.
            triggerDom = dom - 1; 

            if (config.date) {
                const [yyyy, mm, dd] = config.date.split('-').map(Number);
                const d = new Date(yyyy, mm - 1, dd);
                d.setDate(d.getDate() - 1);
                const ny = d.getFullYear();
                const nm = d.getMonth() + 1;
                const nd = d.getDate();
                triggerDateString = `${ny}-${nm < 10 ? '0' + nm : nm}-${nd < 10 ? '0' + nd : nd}`;
            }
        }

        switch (frequency) {
            case 'daily':
                cronExpression = `${tMin} ${tHour} * * *`;
                break;
            case 'weekly':
                cronExpression = `${tMin} ${tHour} * * ${triggerDow}`;
                break;
            case 'monthly':
                if (triggerDom < 1) {
                    console.warn(`[SCHEDULER] Lead time pushed Monthly scan to previous month's end. Reverting to original day for safety.`);
                    cronExpression = `${tMin} ${tHour} ${dom} * *`;
                } else {
                    cronExpression = `${tMin} ${tHour} ${triggerDom} * *`;
                }
                break;
            case 'once':
                if (triggerDateString) {
                    const [yyyy, mm, dd] = triggerDateString.split('-').map(Number);
                    cronExpression = `${tMin} ${tHour} ${dd} ${mm} *`;
                    console.log(`[SCHEDULER] Planned one-time scan for scheduled time ${config.date} at ${hour}:${minute}`);
                    console.log(`[SCHEDULER] Lead time trigger: ${triggerDateString} at ${tHour}:${tMin} (Cron: ${cronExpression})`);
                } else {
                    console.error('[SCHEDULER] Date required for one-time schedule');
                    return;
                }
                break;
            case 'custom':
                 const interval = config.interval || 2;
                 cronExpression = `${tMin} ${tHour} */${interval} * *`;
                 break;
            case 'test':
                cronExpression = '*/5 * * * *'; // Keep test as is 
                break;
            default:
                console.error(`[SCHEDULER] Invalid frequency: ${frequency}`);
                return;
        }

        const timezone = config.timezone || 'UTC';
        // Log for debugging
        console.log(`[SCHEDULER-DEBUG] Scheduling details for ${userId}:`);
        console.log(`  - Platform: ${platform}`);
        console.log(`  - Frequency: ${frequency}`);
        console.log(`  - Time: ${config.time} (Hour: ${hour}, Minute: ${minute})`);
        console.log(`  - Cron Expression: "${cronExpression}"`);
        console.log(`  - Timezone: ${timezone}`);
        console.log(`  - Start Date: ${startDate}`);
        console.log(`  - End Date: ${endDate}`);
        console.log(`  - Email Config: Notify=${config.notifyEmail}, Email=${config.email}`);

        const job = cron.schedule(cronExpression, async () => {
            console.log(`[SCHEDULER-DEBUG] CRON TRIGGERED for ${userId} at ${new Date().toISOString()}`);
            // Check for Expiration
            if (endDate) {
                const end = new Date(endDate);
                end.setHours(23, 59, 59, 999); // End of that day
                if (new Date() > end) {
                    console.log(`[SCHEDULER] Schedule expired for ${userId} (${platform}). Stopping.`);
                    this.stopScan(userId, platform, id);
                    return;
                }
            }

            // Check for Start Date (if future)
            if (startDate) {
                const start = new Date(startDate);
                start.setHours(0, 0, 0, 0);
                if (new Date() < start) {
                     console.log(`[SCHEDULER] Schedule not yet started for ${userId} (${platform}). Skipping.`);
                     return;
                }
            }

            console.log(`[SCHEDULER] Auto-scan triggered for ${userId} (${platform})`);
            
            // Auto-stop if one-time
            if (frequency === 'once') {
                console.log(`[SCHEDULER] One-time scan executed. Removing schedule.`);
                this.stopScan(userId, platform, id);
            }

            try {
                let results;
                const log = (msg) => console.log(`[SCHEDULER-LOG][${userId}] ${msg}`);

                const platformKey = platform ? platform.toUpperCase() : 'UNKNOWN';
                if (platformKey === 'UNKNOWN') {
                    console.error(`[SCHEDULER] Error: Platform is null/undefined for user ${userId}. Skipping.`);
                    return;
                }

                
                // Fallback credential retrieval if missing in config
                let effectiveCreds = credentials || {};
                
                if (platformKey === 'GCP' && !effectiveCreds.keyFileContent) {
                    const mongoose = require('mongoose');
                    const KeyStore = mongoose.model('KeyStore');
                    const User = mongoose.model('User');
                    let storedKey = null;

                    // 0. Try selectedKeyId specifically if provided
                    if (config.selectedKeyId) {
                        storedKey = await KeyStore.findById(config.selectedKeyId);
                        if (storedKey) console.log(`[SCHEDULER] Using specifically selected key for ${userId}: ${storedKey.fileName}`);
                    }
                    
                    if (!storedKey) {
                        // 1. Try User's specific key
                        storedKey = await KeyStore.findOne({ uploadedBy: userId }).sort({ uploadTime: -1 });
                        
                        // 2. If not found, try any key from the same Company
                        if (!storedKey) {
                            const user = await User.findOne({ username: userId });
                            if (user && user.company && user.company !== 'Internal') {
                                // Find any user from the same company who has uploaded a key
                                const companyUsers = await User.find({ company: user.company }).select('username');
                                const usernames = companyUsers.map(u => u.username);
                                storedKey = await KeyStore.findOne({ uploadedBy: { $in: usernames } }).sort({ uploadTime: -1 });
                                if (storedKey) {
                                    console.log(`[SCHEDULER] Using company-level key uploaded by ${storedKey.uploadedBy} for ${userId}`);
                                }
                            }
                        }
                    }

                    if (storedKey && storedKey.keyContent) {
                        effectiveCreds.keyFileContent = typeof storedKey.keyContent === 'string' ? 
                            storedKey.keyContent : JSON.stringify(storedKey.keyContent);
                    }
                } else if (platformKey === 'AWS' && (!effectiveCreds.accessKey || !effectiveCreds.secretKey)) {
                    // Try to find AWS credentials in User model — match by username OR email
                    const mongoose = require('mongoose');
                    const User = mongoose.model('User');
                    const userRecord = await User.findOne({ $or: [{ username: userId }, { email: userId }] });
                    if (userRecord && userRecord.awsCredentials && userRecord.awsCredentials.accessKey) {
                        effectiveCreds.accessKey = userRecord.awsCredentials.accessKey;
                        effectiveCreds.secretKey = userRecord.awsCredentials.secretKey;
                        effectiveCreds.region = userRecord.awsCredentials.region || effectiveCreds.region;
                        console.log(`[SCHEDULER] Using saved AWS credentials for ${userId}`);
                    } else {
                        console.error(`[SCHEDULER] No AWS credentials found for userId: ${userId}`);
                    }
                }
                
                // Email Fallback Logic
                let targetEmail = config.email;
                if (!targetEmail && config.notifyEmail) {
                    // 1. Try if userId is an email
                    if (userId.includes('@')) {
                        targetEmail = userId;
                    } 
                    // 2. Fetch from User record if still not found
                    if (!targetEmail) {
                        try {
                            const mongoose = require('mongoose');
                            const User = mongoose.model('User');
                            const userRecord = await User.findOne({ username: userId });
                            if (userRecord && userRecord.email) {
                                targetEmail = userRecord.email;
                            }
                        } catch (err) {
                            console.error(`[SCHEDULER] Failed to fetch user email for fallback:`, err.message);
                        }
                    }
                    if (targetEmail) {
                         console.log(`[SCHEDULER] Resolved missing email to: ${targetEmail}`);
                    }
                }

                // Execute appropriate audit
                if (platformKey === 'AWS' && effectiveCreds.accessKey && effectiveCreds.secretKey) {
                    results = await this.auditFunctions.aws(effectiveCreds.accessKey, effectiveCreds.secretKey, effectiveCreds.region || 'us-east-1', log);
                } else if (platformKey === 'GCP' && effectiveCreds.keyFileContent) {
                    const fs = require('fs');
                    const path = require('path');
                    const tmpKeyPath = path.join(__dirname, 'uploads', `tmp-sched-${userId}-${Date.now()}.json`);
                    
                    try {
                        fs.writeFileSync(tmpKeyPath, effectiveCreds.keyFileContent);
                        results = await this.auditFunctions.gcp(tmpKeyPath, log);
                    } finally {
                        if (fs.existsSync(tmpKeyPath)) fs.unlinkSync(tmpKeyPath);
                    }
                } else if (platformKey === 'AZURE') {
                    results = await this.auditFunctions.azure(log);
                } else {
                    console.error(`[SCHEDULER] Missing credentials or unsupported platform: ${platform} for user ${userId}`);
                }

                if (results) {
                    // 3. Save Results
                    let summary = { high: 0, medium: 0, low: 0 };
                    if (this.resultHandlers.saveResults) {
                         const saved = await this.resultHandlers.saveResults(userId, config.company || 'Unknown', platform, results);
                         if (saved && saved.summary) summary = saved.summary;
                    }

                    // 4. Update schedule meta
                    if (this.resultHandlers.updateSchedule) {
                        await this.resultHandlers.updateSchedule(userId, platform, {
                            lastScan: new Date()
                        });
                    }

                    // 5. Send Email
                    const emailToSend = targetEmail || config.email; 
                    if (config.notifyEmail && emailToSend) {
                        console.log(`[SCHEDULER] Attempting to send email to ${emailToSend}`);
                        try {
                            await sendSecurityReport(emailToSend, {
                                ...results,
                                platform: platform,
                                summary: summary,
                                timestamp: new Date()
                            });
                             console.log(`[SCHEDULER] Email sent successfully.`);
                        } catch (emailErr) {
                             console.error(`[SCHEDULER] Email sending failed:`, emailErr);
                        }
                    } else {
                        console.log(`[SCHEDULER] Email skipped. Notify=${config.notifyEmail}, Email=${emailToSend}`);
                    }
                }
                return results;
            } catch (err) {
                console.error(`[SCHEDULER] Error during auto-scan for ${userId}:`, err.message);
                throw err;
            }
        }, {
            timezone: timezone
        });

        const key = id || `${userId}-${platform}`;
        this.jobs.set(key, job);
        console.log(`[SCHEDULER] Scheduled ${frequency} scan for ${userId} (${platform}) [Target: ${config.time}, Trigger: ${tHour}:${tMin}, ID: ${id || 'legacy'}]`);
    }

    /**
     * triggerManualScan - Runs a scan immediately without affecting the schedule
     */
    async triggerManualScan(userId, config) {
        const { platform, credentials } = config;
        const log = (msg) => console.log(`[SCHEDULER-MANUAL][${userId}] ${msg}`);
        
        console.log(`[SCHEDULER-V2] Manual trigger for ${userId} (${platform})`);
        console.log(`[SCHEDULER-DEBUG] Config:`, JSON.stringify({ platform, hasCreds: !!credentials }));
        
        const platformKey = platform.toUpperCase();
        console.log(`[SCHEDULER_DEBUG] platformKey: ${platformKey}`);
        console.log(`[SCHEDULER_DEBUG] Available audit functions:`, Object.keys(this.auditFunctions));
        
        let results;
        let effectiveCreds = credentials || {};

        if (platformKey === 'GCP' && !effectiveCreds.keyFileContent) {
            const mongoose = require('mongoose');
            const KeyStore = mongoose.model('KeyStore');
            const User = mongoose.model('User');
            let storedKey = null;

            if (config.selectedKeyId) {
                storedKey = await KeyStore.findById(config.selectedKeyId);
                if (storedKey) console.log(`[SCHEDULER] Using specifically selected key for manual scan for ${userId}: ${storedKey.fileName}`);
            }

            if (!storedKey) {
                storedKey = await KeyStore.findOne({ uploadedBy: userId }).sort({ uploadTime: -1 });
                
                if (!storedKey) {
                    const user = await User.findOne({ username: userId });
                    if (user && user.company && user.company !== 'Internal') {
                        const companyUsers = await User.find({ company: user.company }).select('username');
                        const usernames = companyUsers.map(u => u.username);
                        storedKey = await KeyStore.findOne({ uploadedBy: { $in: usernames } }).sort({ uploadTime: -1 });
                        if (storedKey) console.log(`[SCHEDULER] Using company-level key uploaded by ${storedKey.uploadedBy} for manual scan`);
                    }
                }
            }

            if (storedKey && storedKey.keyContent) {
                effectiveCreds.keyFileContent = typeof storedKey.keyContent === 'string' ? 
                    storedKey.keyContent : JSON.stringify(storedKey.keyContent);
            }
        } 
        
        if (platformKey === 'AWS' && (!effectiveCreds.accessKey || !effectiveCreds.secretKey)) {
            const mongoose = require('mongoose');
            const User = mongoose.model('User');
            // Match by username OR email — userId may be stored either way
            const userRecord = await User.findOne({ $or: [{ username: userId }, { email: userId }] });
            if (userRecord && userRecord.awsCredentials && userRecord.awsCredentials.accessKey) {
                effectiveCreds.accessKey = userRecord.awsCredentials.accessKey;
                effectiveCreds.secretKey = userRecord.awsCredentials.secretKey;
                effectiveCreds.region = userRecord.awsCredentials.region || effectiveCreds.region;
                console.log(`[SCHEDULER-MANUAL] Using saved AWS credentials for ${userId}`);
            } else {
                console.error(`[SCHEDULER-MANUAL] No AWS credentials found for userId: ${userId}`);
            }
        }

        // Email Fallback Logic for Manual Trigger
        let targetEmail = config.email;
        if (!targetEmail && config.notifyEmail) {
            if (userId.includes('@')) {
                targetEmail = userId;
            }
            if (!targetEmail) {
                try {
                    const mongoose = require('mongoose');
                    const User = mongoose.model('User');
                    const userRecord = await User.findOne({ username: userId });
                    if (userRecord && userRecord.email) {
                        targetEmail = userRecord.email;
                    }
                } catch (err) {
                    console.error(`[SCHEDULER] Failed manual user email fallback:`, err.message);
                }
            }
        }

        // --- Execute Scan ---
        if (platformKey === 'AWS' && effectiveCreds.accessKey && effectiveCreds.secretKey) {
            results = await this.auditFunctions.aws(effectiveCreds.accessKey, effectiveCreds.secretKey, effectiveCreds.region || 'us-east-1', log);
        } else if (platformKey === 'GCP' && effectiveCreds.keyFileContent) {
            const fs = require('fs');
            const path = require('path');
            const tmpKeyPath = path.join(__dirname, 'uploads', `tmp-sched-manual-${userId}-${Date.now()}.json`);
            try {
                fs.writeFileSync(tmpKeyPath, effectiveCreds.keyFileContent);
                results = await this.auditFunctions.gcp(tmpKeyPath, log);
            } finally {
                if (fs.existsSync(tmpKeyPath)) fs.unlinkSync(tmpKeyPath);
            }
        } else if (platformKey === 'AZURE') {
            results = await this.auditFunctions.azure(log);
        } else {
            console.error(`[SCHEDULER] No credentials found for ${platformKey} scan for user ${userId}`);
        }

        if (results) {
            const { scanId, summary } = await this.resultHandlers.saveResults(userId, config.company, platform, results);
            
            // Enrich results for email service
            const emailResults = {
                ...results,
                platform: platform,
                summary: summary,
                timestamp: new Date()
            };

            await this.resultHandlers.saveHistory({
                performedBy: userId,
                userEmail: targetEmail || "Manual Scheduler Trigger",
                projectId: results.projectId || results.accountId,
                projectName: results.projectName || results.projectId || `Manual ${platform} Audit`,
                keyName: "Scheduled Scan Triggered Manually",
                scanId: scanId,
                company: config.company,
                platform: platform,
                timestamp: new Date(),
                high: summary.high,
                medium: summary.medium,
                low: summary.low
            });

            if (this.resultHandlers.updateSchedule) {
                await this.resultHandlers.updateSchedule(userId, platform, {
                    lastScan: new Date()
                });
            }

            // 5. Send Email
            const emailToSend = targetEmail || config.email;
            
            console.log(`[SCHEDULER_DEBUG] Preparing to send email. Notify: ${config.notifyEmail}, Email: ${emailToSend}`);
            
            if (config.notifyEmail && emailToSend) {
                console.log(`[SCHEDULER_DEBUG] Sending email to ${emailToSend} for ${platform}`);
                try {
                    await sendSecurityReport(emailToSend, emailResults);
                    console.log(`[SCHEDULER_DEBUG] Email sent successfully.`);
                } catch (emailErr) {
                    console.error(`[SCHEDULER_DEBUG] Email failed:`, emailErr);
                }
            } else {
                console.log(`[SCHEDULER_DEBUG] Email skipped. Notify: ${config.notifyEmail}, Email: ${emailToSend}`);
            }
        }
        return results;
    }

    stopScan(userId, platform, id) {
        const key = id || `${userId}-${platform}`;
        if (this.jobs.has(key)) {
            this.jobs.get(key).stop();
            this.jobs.delete(key);
            console.log(`[SCHEDULER] Stopped schedule for ${userId} (${platform}) [Key: ${key}]`);
        }
    }
}

module.exports = AuditScheduler;
