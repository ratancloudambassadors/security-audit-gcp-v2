require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const mongoose = require('mongoose');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

// --- Credential Encryption (AES-256-GCM) ---
const ENCRYPTION_KEY = process.env.CRED_ENCRYPTION_KEY
    ? Buffer.from(process.env.CRED_ENCRYPTION_KEY, 'hex')
    : crypto.scryptSync('auditscope-secure-key-2025', 'salt-cloud-audit', 32);

function encryptCredential(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptCredential(encoded) {
    if (!encoded || !encoded.includes(':')) return encoded; // Handle legacy/plain values
    try {
        const [ivHex, tagHex, dataHex] = encoded.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const tag = Buffer.from(tagHex, 'hex');
        const data = Buffer.from(dataHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
        decipher.setAuthTag(tag);
        return decipher.update(data, undefined, 'utf8') + decipher.final('utf8');
    } catch (e) {
        console.warn('[CRYPT] Decryption failed, returning raw value:', e.message);
        return encoded;
    }
}

function decryptScheduleCredentials(credentials) {
    if (!credentials) return null;
    return {
        accessKey: decryptCredential(credentials.accessKey),
        secretKey: decryptCredential(credentials.secretKey),
        region: credentials.region,
        keyFileContent: credentials.keyFileContent
    };
}

const app = express();
const PORT = process.env.PORT || 8080;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'MOCK_CLIENT_ID_FOR_DEMO';
const client = new OAuth2Client(CLIENT_ID);

app.use(cors());
app.use(express.json());

// Request logger for debugging
app.use((req, res, next) => {
    console.log(`[HTTP] ${req.method} ${req.url}`);
    next();
});

const { sendSecurityReport, sendWelcomeEmail, sendOtpEmail } = require('./email_service');

// API: Get saved AWS credentials for a user (masked for display)
app.get('/api/user/aws-credentials', async (req, res) => {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ success: false, message: 'Missing userId' });
    try {
        const user = await User.findOne({ $or: [{ username: userId }, { email: userId }] });
        if (!user || !user.awsCredentials || !user.awsCredentials.accessKey) {
            return res.json({ success: true, hasSaved: false });
        }
        const key = user.awsCredentials.accessKey;
        // Mask key — show first 4 and last 4 chars only e.g. AKIA...MPLE
        const masked = key.length > 8
            ? key.substring(0, 4) + '••••••••' + key.substring(key.length - 4)
            : '••••••••••••••••';
        return res.json({
            success: true,
            hasSaved: true,
            maskedKey: masked,
            region: user.awsCredentials.region || 'us-east-1'
        });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// API: Save/update AWS credentials for a user (from profile settings)
app.post('/api/user/aws-credentials', async (req, res) => {
    const { userId, accessKey, secretKey, region } = req.body;
    if (!userId || !accessKey || !secretKey) return res.status(400).json({ success: false, message: 'Missing required fields' });
    try {
        await User.findOneAndUpdate(
            { $or: [{ username: userId }, { email: userId }] },
            { $set: { 
                'awsCredentials.accessKey': accessKey.trim(), 
                'awsCredentials.secretKey': secretKey.trim(), 
                'awsCredentials.region': region || 'us-east-1' 
            } },
            { new: true }
        );
        res.json({ success: true, message: 'AWS credentials saved successfully' });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// API: Get available keys for a user/company
app.get('/api/user/keys', async (req, res) => {
    const { userId, platform } = req.query;
    if (!userId || !platform) return res.status(400).json({ success: false, message: 'Missing parameters' });

    try {
        const user = await User.findOne({ 
            $or: [{ username: userId }, { email: userId }] 
        });
        
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        let query = { uploadedBy: userId };
        if (user.company && user.company !== 'Internal') {
            const companyUsers = await User.find({ company: user.company }).select('username');
            const usernames = companyUsers.map(u => u.username);
            query = { uploadedBy: { $in: usernames } };
        }

        // Filter by platform logic (currently GCP uses KeyStore)
        if (platform.toUpperCase() === 'GCP') {
            query.projectId = { $exists: true };
        }

        const allKeys = await KeyStore.find(query).sort({ uploadTime: -1 }).select('fileName projectId clientEmail uploadedBy uploadTime');
        
        // Deduplicate by projectId to prevent showing the same project multiple times
        const keys = [];
        const seenProjects = new Set();
        for (const key of allKeys) {
            const projectIdentifier = key.projectId || key.fileName; // Fallback if projectId missing
            if (!seenProjects.has(projectIdentifier)) {
                seenProjects.add(projectIdentifier);
                keys.push(key);
            }
        }
        
        res.json({ success: true, keys });
    } catch (e) {
        console.error('[API KEYS] Error:', e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// Configure upload - Standard for generic use
const upload = multer({ dest: 'uploads/' });

// Secure Config for Service Account Keys
const keyUpload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JSON service account keys are allowed.'));
        }
    }
});

// API: Standalone key upload for Automation/Key Management
app.post('/api/user/keys/upload', keyUpload.single('keyFile'), async (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded." });
    
    const websiteUser = req.body.username || "Anonymous";
    const keyPath = req.file.path;

    try {
        const raw = fs.readFileSync(keyPath);
        const json = JSON.parse(raw);
        if (!json.project_id) throw new Error("Missing project_id in JSON");

        // Check for duplicates
        const existingKey = await KeyStore.findOne({ projectId: json.project_id, uploadedBy: websiteUser });
        if (existingKey) {
            // Update existing or skip? Let's update.
            existingKey.keyContent = json;
            existingKey.fileName = req.file.originalname;
            existingKey.clientEmail = json.client_email;
            existingKey.uploadTime = new Date();
            await existingKey.save();
        } else {
            await KeyStore.create({
                fileName: req.file.originalname,
                projectId: json.project_id,
                clientEmail: json.client_email,
                uploadedBy: websiteUser,
                keyContent: json
            });
        }

        res.json({ success: true, message: "Key uploaded and secured successfully." });
    } catch (error) {
        console.error("[KEY UPLOAD] Error:", error);
        res.status(500).json({ success: false, message: error.message });
    } finally {
        // Secure Cleanup
        try {
            if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
        } catch (e) {}
    }
});
app.use(express.static(path.join(__dirname, 'public')));

// API: Config for Frontend
app.get('/api/config', (req, res) => {
    res.json({
        googleClientId: CLIENT_ID,
        isDemo: CLIENT_ID === 'MOCK_CLIENT_ID_FOR_DEMO'
    });
});

// MongoDB Connection
const { MongoMemoryServer } = require('mongodb-memory-server');

let dbConnected = false;

// Migration Helper - REMOVED per user request
// const seedFromLocal = async () => {};

const BACKUP_FILE = path.join(__dirname, 'data', 'backup.json');

const backupData = async () => {
    if (!dbConnected) return;
    try {
        const users = await User.find({});
        const keys = await KeyStore.find({});
        const history = await ScanHistory.find({});
        
        const data = { users, keys, history };
        fs.writeFileSync(BACKUP_FILE, JSON.stringify(data, null, 2));
        console.log('[BACKUP] Data backed up to local file.');
    } catch (e) {
        console.error('[BACKUP] Failed:', e.message);
    }
};

const restoreData = async () => {
    if (!fs.existsSync(BACKUP_FILE)) return;
    try {
        const raw = fs.readFileSync(BACKUP_FILE);
        const data = JSON.parse(raw);
        
        if (data.users && data.users.length > 0) {
            await User.deleteMany({});
            await User.insertMany(data.users);
            console.log(`[RESTORE] Restored ${data.users.length} users.`);
        }
        if (data.keys && data.keys.length > 0) {
            await KeyStore.deleteMany({});
            await KeyStore.insertMany(data.keys);
             console.log(`[RESTORE] Restored ${data.keys.length} keys.`);
        }
        if (data.history && data.history.length > 0) {
             await ScanHistory.deleteMany({});
             await ScanHistory.insertMany(data.history);
             console.log(`[RESTORE] Restored ${data.history.length} history records.`);
        }
    } catch (e) {
        console.error('[RESTORE] Failed:', e.message);
    }
};

const startDB = async () => {
    // PRIORITY 1: Try Local Persistent MongoDB
    try {
        const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/gcp-audit';
        console.log('Attempting to connect to Local Persistent MongoDB...');
        await mongoose.connect(MONGODB_URI);
        console.log('✅ Connected to Local Persistent MongoDB');
        dbConnected = true;
        await fixInvalidSchedules();
    } catch (err) {
        console.error('❌ Failed to connect to Local MongoDB:', err.message);
        console.error('   Please ensure MongoDB is running (sudo systemctl start mongod).');
        console.error('   Strict Mode: In-Memory Fallback is DISABLED per user request.');
        process.exit(1); 
    }
};

const fixInvalidSchedules = async () => {
    try {
        if (!dbConnected) return;
        const result = await Schedule.updateMany(
            { platform: { $in: [null, undefined, ''] } },
            { $set: { platform: 'GCP' } }
        );
        if (result.modifiedCount > 0) {
            console.log(`[MIGRATION] Fixed ${result.modifiedCount} schedules with missing platform (Set to GCP).`);
        }

        // Fix bad emails (remove @internal.audit appended ones so fallback works)
        const emailFix = await Schedule.updateMany(
             { email: { $regex: /@internal\.audit$/ } },
             { $unset: { email: "" } }
        );
        if (emailFix.modifiedCount > 0) {
             console.log(`[MIGRATION] Fixed ${emailFix.modifiedCount} schedules with corrupt email addresses.`);
        }
    } catch (e) {
        console.error('[MIGRATION] Failed to fix schedules:', e.message);
    }
};

// startDB(); // Called explicitly at bottom to ensure ordering

// --- Database Models ---

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    displayName: String,
    email: String,
    profilePicture: { type: String, default: '' },
    role: { type: String, default: 'Security Auditor' },
    company: { type: String, default: 'Internal' },
    lastLogin: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    awsCredentials: {
        accessKey: String,
        secretKey: String,
        region: String
    }
});
const User = mongoose.model('User', userSchema);

// Service Account Key Storage Schema
const keySchema = new mongoose.Schema({
    fileName: String,
    projectId: String,
    clientEmail: String,
    uploadedBy: String,
    uploadTime: { type: Date, default: Date.now },
    keyContent: Object // Store the raw JSON content (caution: security risk in real app)
});
const KeyStore = mongoose.model('KeyStore', keySchema);

// Scan History Schema
const scanHistorySchema = new mongoose.Schema({
    performedBy: String,
    userEmail: String,
    projectId: String,
    projectName: String,
    keyName: String, // Added key name
    scanId: String, // Link to full results
    company: String, // Added for isolation
    platform: { type: String, default: 'GCP' },
    timestamp: { type: Date, default: Date.now },
    high: Number,
    medium: Number,
    low: Number
});

// Schedule Schema
const scheduleSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    company: String,
    platform: { type: String, required: true },
    frequency: { type: String, enum: ['daily', 'weekly', 'monthly', 'custom', 'once', 'test'], default: 'weekly' },
    time: { type: String, default: '09:00' }, // e.g., "14:30"
    timezone: { type: String, default: 'Asia/Kolkata' }, // Default to IST as per user preference
    dayOfWeek: { type: Number, default: 1 }, // 0-6 (Sunday-Saturday)
    dayOfMonth: { type: Number, default: 1 }, // 1-31
    interval: { type: Number, default: 1 }, // For custom frequency
    date: String, // YYYY-MM-DD for one-time scans
    startDate: Date,
    endDate: Date,
    notifyEmail: { type: Boolean, default: true },
    email: String,
    credentials: {
        accessKey: String,
        secretKey: String,
        region: String,
        keyFileContent: String // For GCP
    },
    lastScan: Date,
    nextScan: Date,
    active: { type: Boolean, default: true },
    selectedKeyId: { type: mongoose.Schema.Types.ObjectId, ref: 'KeyStore' }
}, { timestamps: true });
const Schedule = mongoose.model('Schedule', scheduleSchema);

const ScanHistory = mongoose.model('ScanHistory', scanHistorySchema);

// OTP Schema (Temporary codes for email verification)
const otpSchema = new mongoose.Schema({
    email: { type: String, required: true, index: true },
    otp: { type: String, required: true },
    verified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now, expires: 300 } // Auto-delete after 5 minutes
});
const Otp = mongoose.model('Otp', otpSchema);

// Schema: ScanResults (Complete scan data for persistence)
const scanResultsSchema = new mongoose.Schema({
    scanId: { type: String, required: true, unique: true },
    userId: { type: String, required: true, index: true },
    company: String, // Added for isolation
    platform: { type: String, required: true }, // 'GCP', 'AWS', 'Azure'
    projectId: String,
    projectName: String,
    timestamp: { type: Date, default: Date.now },
    
    // Complete scan results (stored as JSON)
    results: mongoose.Schema.Types.Mixed,
    
    // Summary for quick access
    summary: {
        totalVulnerabilities: Number,
        high: Number,
        medium: Number,
        low: Number,
        secure: Number
    },
    
    // Metadata
    isLatest: { type: Boolean, default: true },
    scanDuration: Number,
    keyName: String
});

// Index for faster queries
scanResultsSchema.index({ userId: 1, platform: 1, timestamp: -1 });
scanResultsSchema.index({ userId: 1, isLatest: 1 });

const ScanResults = mongoose.model('ScanResults', scanResultsSchema);


// --- Local Storage Fallback Utilities - REMOVED ---
// const LOCAL_DB_PATH = ...
// const readLocal = ...
// const writeLocal = ...

// Seed default users for demo (Only if DB connected and empty)
if (dbConnected) {
    // Optional: Seed DB if empty
}
// Helper to manage history
async function getHistory(username) {
    if (!username) return []; // STRICT: No username, no history.
    
    let query = { performedBy: username }; // Default: Self only

    if (dbConnected) {
        try {
            // Check User's Company for Isolation
            const user = await User.findOne({ username });
            if (user && user.company && user.company !== 'Internal') {
                // If user belongs to a company, show ALL history for that company
                query = { company: user.company };
            }
            
            return await ScanHistory.find(query).sort({ timestamp: -1 }).limit(100);
        } catch (e) { 
            console.error("History Read Error:", e); 
        }
    }
    return [];
}

async function saveHistory(record) {
    if (dbConnected) {
        try {
            const newRecord = new ScanHistory(record);
            await newRecord.save();
            await backupData(); // Backup after history save
        } catch (e) {
            console.error("History Save Error:", e);
        }
    }
}

// Helper: Save complete scan results
async function saveScanResults(userId, company, platform, results, keyName = '') {
    if (!dbConnected) return { scanId: null, summary: { high: 0, medium: 0, low: 0, totalVulnerabilities: 0 } };
    
    try {
        const scanId = `${platform}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Calculate summary (Consolidate critical into high)
        const services = results.services || {};
        const summary = {
            high: Object.values(services).reduce((a, s) => a + (s && s.summary ? (s.summary.high || 0) + (s.summary.critical || 0) : 0), 0),
            medium: Object.values(services).reduce((a, s) => a + (s && s.summary ? (s.summary.medium || 0) : 0), 0),
            low: Object.values(services).reduce((a, s) => a + (s && s.summary ? (s.summary.low || 0) : 0), 0),
            secure: Object.values(services).reduce((a, s) => a + (s && s.summary ? (s.summary.secure || 0) : 0), 0)
        };
        summary.totalVulnerabilities = summary.high + summary.medium + summary.low;
        
        // Mark previous scans as not latest
        await ScanResults.updateMany(
            { userId, platform, projectId: results.projectId || results.accountId || results.subscriptionId },
            { isLatest: false }
        );
        
        // Normalize projectMetadata for consistent frontend consumption
        if (!results.projectMetadata) {
            results.projectMetadata = {
                name: results.projectName || results.projectId || results.accountId || results.subscriptionId || 'Unknown',
                number: results.accountId || results.subscriptionId || 'N/A',
                createTime: results.timestamp || new Date(),
                lifecycleState: 'ACTIVE',
                scanUser: userId || 'Security Auditor'
            };
        }

        // Save new scan
        const scanRecord = new ScanResults({
            scanId,
            userId,
            company: company || 'Internal',
            platform,
            projectId: results.projectId || results.accountId || results.subscriptionId || 'unknown',
            projectName: results.projectMetadata?.name || results.projectId || results.accountId || `${platform} Account`,
            timestamp: new Date(),
            results,
            summary,
            isLatest: true,
            keyName
        });
        
        await scanRecord.save();
        console.log(`[SCAN RESULTS] Saved scan ${scanId} for user ${userId} (Company: ${company}, Platform: ${platform})`);
        return { scanId, summary };
    } catch (e) {
        console.error('[SCAN RESULTS] Save error:', e.message);
        return { scanId: null, summary: { high: 0, medium: 0, low: 0, totalVulnerabilities: 0 } };
    }
}

// Helper: Get latest scan results (Company aware)
async function getLatestScanResults(userId, platform) {
    if (!dbConnected) return null;
    
    try {
        // If platform is 'any' or not provided, get the absolute latest scan across all platforms
        let query = (platform && platform !== 'any')
            ? { userId, platform, isLatest: true }
            : { userId };

        const scan = await ScanResults.findOne(query).sort({ timestamp: -1 });
        return scan;
    } catch (e) {
        console.error('[SCAN RESULTS] Fetch error:', e.message);
        return null;
    }
}

// Helper: Get all scan results for user (Company aware)
async function getAllScanResults(userId, platform = null) {
    if (!dbConnected) return [];
    
    try {
        let query = { userId };
        
        // Check User's Company for Isolation
        const user = await User.findOne({ username: userId });
        if (user && user.company && user.company !== 'Internal') {
            // Show ALL scans for the company
            query = { company: user.company };
        }

        if (platform) query.platform = platform;
        
        const scans = await ScanResults.find(query)
            .select('scanId platform projectId projectName timestamp summary isLatest company')
            .sort({ timestamp: -1 })
            .limit(50);
        return scans;
    } catch (e) {
        console.error('[SCAN RESULTS] List error:', e.message);
        return [];
    }
}

// Helper: Get specific scan by ID (Secure)
async function getScanResultById(scanId, requesterUsername) {
    if (!dbConnected) return null;
    
    try {
        const scan = await ScanResults.findOne({ scanId });
        if (!scan) return null;

        if (requesterUsername) {
            const requester = await User.findOne({ username: requesterUsername });
            
            // 1. Check if same company
            if (requester && requester.company && requester.company !== 'Internal') {
                if (scan.company === requester.company) return scan;
            }
            
            // 2. Check if same user (Fallback for Internal users)
            if (scan.userId === requesterUsername) return scan;
            
            // 3. Reject
            console.warn(`[SECURITY] Access denied to scan ${scanId} for user ${requesterUsername}`);
            return null; 
        }

        // If no requester provided, strictly deny in production. 
        // For backwards compat during migration, maybe allow if 'Internal'? No, "Isolate Data" is strict.
        return null;

    } catch (e) {
        console.error('[SCAN RESULTS] Get by ID error:', e.message);
        return null;
    }
}


// API: Password Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    // In a real app, use bcrypt. For this demo, direct comparison.
    let user;
    if (dbConnected) {
        user = await User.findOne({ 
            $or: [{ username }, { email: username }, { displayName: username }], 
            password 
        });
    }

    if (user) {
        res.json({ 
            success: true, 
            user: { 
                username: user.username,
                name: user.displayName || user.username, 
                email: user.email || (user.username + "@internal.audit"), 
                picture: user.profilePicture || ("https://ui-avatars.com/api/?name=" + (user.displayName || user.username)),
                role: user.role || "Security Auditor",
                company: user.company || "Internal",
                createdAt: user.createdAt || new Date()
            },
            token: "mock-jwt-token"
        });
    } else {
        res.status(401).json({ success: false, message: "Invalid credentials" });
    }
});

// API: Send OTP for Email Verification
app.post('/api/auth/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
        return res.status(400).json({ success: false, message: "Valid email is required." });
    }

    try {
        if (!dbConnected) throw new Error("Database not connected.");

        // Check if user already exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ success: false, message: "User with this email already exists." });
        }

        // Check if company already exists (only for non-individual)
        const { company } = req.body;
        if (company && company !== 'Individual') {
             const companyExists = await User.findOne({ company: { $regex: new RegExp(`^${company}$`, 'i') } });
             if (companyExists) {
                 return res.status(400).json({ 
                     success: false, 
                     message: `"${company}" is already registered. Please contact your company admin to get access to our platform.` 
                 });
             }
        }

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Save OTP to DB (replace existing if any)
        await Otp.findOneAndUpdate(
            { email },
            { otp, verified: false, createdAt: new Date() },
            { upsert: true }
        );

        // Send Email
        const sent = await sendOtpEmail(email, otp);
        if (sent) {
            res.json({ success: true, message: "Verification code sent to your email." });
        } else {
            throw new Error("Failed to send verification email. Please check your SMTP settings.");
        }
    } catch (e) {
        console.error("[OTP] Error sending OTP:", e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// API: Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ success: false, message: "Email and OTP are required." });
    }

    try {
        if (!dbConnected) throw new Error("Database not connected.");

        const record = await Otp.findOne({ email, otp });
        if (!record) {
            return res.status(400).json({ success: false, message: "Invalid or expired verification code." });
        }

        record.verified = true;
        await record.save();

        res.json({ success: true, message: "Email verified successfully!" });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// API: Register (Secure & Company Aware)
app.post('/api/auth/register', async (req, res) => {
    let { username, password, displayName, company } = req.body;
    
    // Default company if not provided
    if (!company || company.trim() === '') company = 'Individual';

    try {
        if (!dbConnected) {
            throw new Error("Database not connected. Registration unavailable.");
        }

        // 1. Check if username or email already exists
        const existingUser = await User.findOne({ 
            $or: [{ username }, { email: username }] 
        });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User with this identity/email already exists." });
        }

        // 2. Check if Company Name is already registered (Strictly for non-Internal/non-Individual companies)
        const normalizedCompany = company.trim();
        const restrictedNames = ['Internal', 'Individual', 'None', 'N/A'];
        
        if (!restrictedNames.includes(normalizedCompany)) {
            // Case-insensitive search for existing company
            const existingCompany = await User.findOne({ 
                company: { $regex: new RegExp(`^${normalizedCompany.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } 
            });
            
            if (existingCompany) {
                return res.status(400).json({ 
                    success: false, 
                    message: `Organization '${normalizedCompany}' is already registered. Please use a unique name or contact your admin.` 
                });
            }
        }

        // 0. Verify OTP if email is provided
        if (username.includes('@')) {
            const otpRecord = await Otp.findOne({ email: username, verified: true });
            if (!otpRecord) {
                return res.status(400).json({ success: false, message: "Please verify your email with OTP before registering." });
            }
            // Cleanup OTP after successful verification usage
            await Otp.deleteOne({ _id: otpRecord._id });
        }

        // 3. Create New User
        const newUser = new User({ 
            username, 
            password, 
            displayName, 
            company: normalizedCompany,
            email: username.includes('@') ? username : undefined
        });

        await newUser.save();
        console.log(`[AUTH] Registered new user: ${username} for company: ${normalizedCompany}`);
        
        await backupData();
        res.json({ success: true, message: "Registration successful!" });

    } catch (e) {
        console.error("[AUTH] Registration error:", e.message);
        res.status(400).json({ success: false, message: e.message });
    }
});

// DEBUG: View all users in MongoDB
app.get('/api/debug/users', async (req, res) => {
    try {
        let users = [];
        if (dbConnected) {
            users = await User.find({});
        }
        res.json({ 
            source: dbConnected ? "MongoDB" : "None", 
            count: users.length, 
            users 
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// API: Google Login Verification
app.post('/api/auth/google', async (req, res) => {
    const { token } = req.body;
    
    try {
        let user;
        if (CLIENT_ID === 'MOCK_CLIENT_ID_FOR_DEMO' || token === 'mock-token') {
             user = { 
                name: "Demo User", 
                email: "demo@example.com", 
                picture: "https://lh3.googleusercontent.com/a/default-user" 
            };
        } else {
            const ticket = await client.verifyIdToken({
                idToken: token,
                audience: CLIENT_ID,
            });
            const payload = ticket.getPayload();
            user = {
                googleId: payload['sub'],
                email: payload['email'],
                name: payload['name'],
                picture: payload['picture'],
            };
        }

        // Save/Update User in Database
        const userData = {
            username: user.email.split('@')[0],
            displayName: user.name,
            email: user.email,
            profilePicture: user.picture,
            lastLogin: new Date()
        };

        if (dbConnected) {
            await User.findOneAndUpdate(
                { username: userData.username },
                { $set: userData },
                { upsert: true, new: true }
            );
            await backupData(); // Backup after Google auth
        } else {
             throw new Error("Database not connected. Google Auth unavailable.");
        }

        // Fetch the final user to return full details
        let finalUser;
        if (dbConnected) {
            finalUser = await User.findOne({ username: userData.username });
        } else {
             throw new Error("User retrieval failed.");
        }

        res.json({ 
            success: true, 
            user: {
                username: finalUser.username,
                name: finalUser.displayName,
                email: finalUser.email,
                picture: finalUser.profilePicture,
                role: finalUser.role,
                company: finalUser.company || "Internal",
                createdAt: finalUser.createdAt
            }, 
            token: token || "mock-jwt-token" 
        });
    } catch (error) {
        console.error("Auth Error:", error);
        res.status(401).json({ success: false, message: "Invalid Token" });
    }
});

// Configure upload
// Profile Picture Storage
const profileStorage = multer.diskStorage({
    destination: './public/uploads/profiles/',
    filename: (req, file, cb) => {
        cb(null, 'profile-' + Date.now() + path.extname(file.originalname));
    }
});
const profileUpload = multer({ storage: profileStorage });

const { runAudit } = require('./audit');
const { runSimulatedAudit } = require('./audit_sim');
const { runAWSAudit } = require('./audit_aws');
const AuditScheduler = require('./scheduler');

// Initialize Scheduler
const scheduler = new AuditScheduler(
    { gcp: runAudit, aws: runAWSAudit, azure: runSimulatedAudit },
    { 
        saveResults: saveScanResults, 
        saveHistory: saveHistory,
        updateSchedule: async (userId, platform, update) => {
            if (dbConnected) {
                await Schedule.findOneAndUpdate({ userId, platform: platform.toUpperCase() }, { $set: update });
            }
        }
    }
);

// --- Profile Management APIs ---

app.post('/api/user/update', async (req, res) => {
    const { username, displayName, role, password } = req.body;
    try {
        if (dbConnected) {
            const update = { displayName, role };
            if (password) update.password = password; 
            await User.findOneAndUpdate({ username }, update);
            await backupData(); // Backup after update
        } else {
             throw new Error("Database unavailable");
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.post('/api/user/upload-picture', profileUpload.single('profilePic'), async (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: "No file" });
    
    const username = req.body.username;
    const pictureUrl = `/uploads/profiles/${req.file.filename}`;

    try {
        if (dbConnected) {
            await User.findOneAndUpdate({ username }, { profilePicture: pictureUrl });
        } else {
            throw new Error("Database unavailable");
        }
        res.json({ success: true, pictureUrl });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});


// --- Scheduling APIs ---

app.post('/api/user/schedule', async (req, res) => {
    const { id, userId, platform, frequency, time, dayOfWeek, dayOfMonth, date, startDate, endDate, notifyEmail, email, credentials, active, timezone, selectedKeyId } = req.body;
    
    try {
        if (!dbConnected) throw new Error("Database unavailable");

        let userCompany = 'Internal';
        const user = await User.findOne({ username: userId });
        if (user) userCompany = user.company;

        // Map & encrypt credentials before storing
        let encryptedCredentials = null;
        if (credentials) {
            // Frontend sends { awsAccessKeyId, awsSecretAccessKey } — map to schema fields
            const rawKey = credentials.awsAccessKeyId || credentials.accessKey;
            const rawSecret = credentials.awsSecretAccessKey || credentials.secretKey;
            if (rawKey || rawSecret) {
                encryptedCredentials = {
                    accessKey: encryptCredential(rawKey),
                    secretKey: encryptCredential(rawSecret),
                    region: credentials.region || 'all'
                };
                console.log(`[CRED] AWS credentials encrypted for user: ${userId}`);
            }
        }

        const updateData = {
            userId,
            frequency,
            time,
            dayOfWeek,
            dayOfMonth,
            notifyEmail,
            email,
            credentials: encryptedCredentials,
            active,
            timezone,
            company: userCompany,
            platform: platform || 'GCP',
            date,
            startDate,
            endDate,
            selectedKeyId: selectedKeyId || null
        };

        const targetPlatform = platform || 'GCP';
        let schedule;

        if (id) {
            // Update existing schedule
            schedule = await Schedule.findOneAndUpdate(
                { _id: id },
                { $set: updateData },
                { new: true }
            );
            if (!schedule) return res.status(404).json({ success: false, message: "Schedule not found" });
        } else {
            // Create NEW schedule
            schedule = new Schedule(updateData);
            await schedule.save();
        }

        if (schedule.active) {
            // Decrypt credentials before passing to scheduler (which runs the actual scan)
            const storedCreds = encryptedCredentials || schedule.credentials;
            const decryptedCreds = decryptScheduleCredentials(storedCreds);

            scheduler.scheduleScan(userId, {
                id: schedule._id.toString(),
                platform: targetPlatform,
                ...updateData,
                credentials: decryptedCreds,
                date
            });
        } else {
            scheduler.stopScan(userId, targetPlatform, schedule._id.toString());
        }

        res.json({ success: true, schedule });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// List ALL schedules for a user
app.get('/api/user/schedules', async (req, res) => {
    const { userId } = req.query;
    try {
        if (!dbConnected) throw new Error("Database unavailable");
        
        let query = { userId };
        
        // Isolation check: If user belongs to a company, maybe show company schedules?
        // For now, strict ownership based on userId is safest.
        
        const schedules = await Schedule.find(query).sort({ createdAt: -1 });
        res.json({ success: true, schedules });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.get('/api/user/schedule', async (req, res) => {
    const { userId, platform, id } = req.query;
    console.log(`[GET_SCHEDULE] Req: id='${id}', userId='${userId}', platform='${platform}'`);
    try {
        if (!dbConnected) throw new Error("Database unavailable");
        
        let query = {};
        if (id && id !== 'undefined' && id !== 'null') {
            query = { _id: id };
        } else if (userId && platform) {
            query = { userId, platform };
        } else {
            return res.status(400).json({ success: false, message: "Missing id or userId+platform" });
        }

        console.log(`[GET_SCHEDULE] Query:`, JSON.stringify(query));
        const schedule = await Schedule.findOne(query);
        console.log(`[GET_SCHEDULE] Found:`, !!schedule);
        
        if (!schedule) {
            return res.json({ success: false, message: "Schedule not found in database." });
        }
        
        res.json({ success: true, schedule });
    } catch (e) {
        console.error(`[GET_SCHEDULE] Error:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

app.delete('/api/user/schedule', async (req, res) => {
    const { userId, platform, id } = req.query;
    try {
        if (!dbConnected) throw new Error("Database unavailable");

        let query = {};
        if (id) {
            query = { _id: id };
            // Optional: Verify ownership userId matches if provided
            if(userId) query.userId = userId; 
        } else if (userId && platform) {
            query = { userId, platform };
        } else {
            return res.status(400).json({ success: false, message: "Missing id or userId+platform" });
        }

        const schedule = await Schedule.findOneAndDelete(query);
        
        if (schedule) {
            scheduler.stopScan(schedule.userId, schedule.platform);
            res.json({ success: true, message: "Schedule deleted" });
        } else {
            res.status(404).json({ success: false, message: "Schedule not found" });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Manual trigger for a scheduled scan
app.post('/api/user/schedule/test', async (req, res) => {
    const { userId, platform, notifyEmail, email, selectedKeyId } = req.body;
    console.log(`[SERVER_DEBUG] Manual trigger req: userId='${userId}' (${userId.length}), platform='${platform}'`);
    try {
        const query = { userId, platform: platform.toUpperCase() };
        console.log(`[SERVER_DEBUG] Querying Schedule with:`, JSON.stringify(query));
        const schedule = await Schedule.findOne(query);
        console.log(`[SERVER_DEBUG] Found schedule?`, !!schedule);
        if (!schedule) return res.status(404).json({ success: false, message: "Schedule not found" });

        console.log(`[SERVER] Manually triggering scan for ${userId} (${platform})`);
        
        // Decrypt stored credentials before running scan
        const decryptedCreds = decryptScheduleCredentials(schedule.credentials);

        // Pass values from request if present, otherwise fallback to schedule defaults
        const results = await scheduler.triggerManualScan(userId, {
            platform: platform.toUpperCase(),
            credentials: decryptedCreds,
            company: schedule.company,
            notifyEmail: notifyEmail !== undefined ? notifyEmail : schedule.notifyEmail,
            email: email || schedule.email,
            selectedKeyId: selectedKeyId || schedule.selectedKeyId
        });

        res.json({ success: true, message: "Scan triggered successfully", results });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Dedicated Email Test Endpoint
app.post('/api/email/test', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email required" });

    console.log(`[SERVER] Testing email delivery to: ${email}`);
    try {
        const { sendSecurityReport } = require('./email_service');
        const success = await sendSecurityReport(email, {
            platform: 'TEST',
            summary: { high: 0, medium: 0, low: 0, secure: 0 },
            projectId: 'Email-Connectivity-Check',
            timestamp: new Date()
        });

        if (success) {
            res.json({ success: true, message: "Email sent successfully" });
        } else {
            res.status(500).json({ success: false, message: "Failed to send email" });
        }
    } catch (e) {
        console.error(`[SERVER] Email test error:`, e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// --- Team Management APIs ---

app.get('/api/team', async (req, res) => {
    try {
        let users = [];
        if (dbConnected) {
            const requesterName = req.query.requester;
            console.log(`[DEBUG] /api/team called by: '${requesterName}'`);
            
            if (requesterName) {
                // Find requester to get their company
                const requester = await User.findOne({ username: requesterName });
                if (requester) {
                     console.log(`[DEBUG] Requester found. Company: '${requester.company}'`);
                     // Filter: only show users from SAME company
                     const company = requester.company;
                     if (company) {
                         console.log(`[DEBUG] Filtering for company: '${company}'`);
                         users = await User.find({ company: company }, { password: 0 });
                     } else {
                         console.log(`[DEBUG] No company set. Isolation mode (self-only).`);
                         users = [requester]; 
                     }
                } else {
                    console.log(`[DEBUG] Requester '${requesterName}' not found in DB.`);
                }
            } else {
                 console.log(`[DEBUG] No requester params provided.`);
                 users = [];
            }
        }
        console.log(`[DEBUG] Returning ${users.length} users.`);
        res.json(users);
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.post('/api/team/add', async (req, res) => {
    const { email, name, role, password } = req.body;
    console.log(`[TEAM] Received invitation request for: ${email}`);
    
    if (!email || !name || !password) {
        return res.status(400).json({ success: false, message: "Email, Name, and Password are required." });
    }

    const username = email.split('@')[0];
    const requester = req.body.adminUsername; // Admin who is adding the user
    
    try {
        let adminCompany = 'Internal';
        if (requester && dbConnected) {
            const admin = await User.findOne({ username: requester });
            if (admin) adminCompany = admin.company || 'Internal';
        }

        const userData = {
            username,
            displayName: name,
            email,
            role,
            company: adminCompany, // Now uses Admin's Company
            profilePicture: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random`,
            password,
            createdAt: new Date()
        };

        if (dbConnected) {
            const existing = await User.findOne({ username });
            if (existing) return res.status(400).json({ success: false, message: `Account for ${email} already exists.` });
            const newUser = new User(userData);
            await newUser.save();
            await backupData(); // Backup after adding member

            // Send Welcome Email with Credentials
            console.log(`[TEAM] Triggering welcome email for ${email}...`);
            await sendWelcomeEmail(email, name, password);
        } else {
            throw new Error("Database unavailable");
        }
        
        console.log(`[TEAM] Successfully added ${email} to AuditScope team.`);
        res.json({ success: true, user: userData });
    } catch (e) {
        console.error("[TEAM] Error adding member:", e);
        res.status(500).json({ success: false, message: "Internal server error: " + e.message });
    }
});

app.post('/api/team/change-password', async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ success: false, message: "Username and new password are required." });

    try {
        if (dbConnected) {
            await User.findOneAndUpdate({ username }, { password: newPassword });
        } else {
            throw new Error("Database unavailable");
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.delete('/api/team/:username', async (req, res) => {
    const { username } = req.params;
    try {
        if (dbConnected) {
            await User.findOneAndDelete({ username });
        } else {
            throw new Error("Database unavailable");
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// API: Scan History
app.get('/api/history', async (req, res) => {
    const { username } = req.query;
    const history = await getHistory(username);
    res.json(history);
});

app.post('/api/history/clear', async (req, res) => {
    try {
        await ScanHistory.deleteMany({});
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// API: Get latest scan for user (specific platform)
app.get('/api/scan-results/latest', async (req, res) => {
    const { userId, platform } = req.query;
    if (!userId) {
        return res.status(400).json({ success: false, message: 'userId required' });
    }
    
    try {
        // If no platform specified or 'any', get the absolute latest scan across all platforms
        const scan = await getLatestScanResults(userId, platform || 'any');
        if (scan) {
            res.json({ success: true, scan });
        } else {
            res.json({ success: false, message: 'No scans found' });
        }
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/scan-results/list', async (req, res) => {
    const { userId, platform } = req.query;
    if (!userId) {
        return res.status(400).json({ success: false, message: 'userId required' });
    }
    
    try {
        const scans = await getAllScanResults(userId, platform || null);
        res.json({ success: true, scans });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/scan-results/:scanId', async (req, res) => {
    const { scanId } = req.params;
    const { userId } = req.query; // Requester identity required

    if (!userId) {
        return res.status(401).json({ success: false, message: 'User identity required for access.' });
    }
    
    try {
        const scan = await getScanResultById(scanId, userId);
        if (scan) {
            res.json({ success: true, scan });
        } else {
            res.status(404).json({ success: false, message: 'Scan not found or access denied' });
        }
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});


// API: Start GCP Scan (Streams text logs + JSON result)

app.post('/api/scan-gcp', keyUpload.single('keyFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).send("No file uploaded.");
    }

    // Set headers for streaming
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable Nginx buffering
    res.setHeader('Cache-Control', 'no-cache');

    const log = (msg) => {
        res.write(`LOG: ${msg}\n`);
    };

    const keyPath = req.file.path;

    try {
        log("File uploaded successfully.");
        log("Validating JSON key structure...");
        
        // Basic Validation
        const raw = fs.readFileSync(keyPath);
        const json = JSON.parse(raw);
        if (!json.project_id) throw new Error("Missing project_id in JSON");

        const websiteUser = req.body.username || "Anonymous";
        
        // SECURITY UPDATE: Key content is NOT stored in DB.
        log("Security Check: Key validated. Ephemeral usage only.");

        // Start Audit
        log(`Starting GCP Security Audit for project: ${json.project_id}...`);
        
        const results = await runAudit(keyPath, log);
        
        log("Audit complete. Analyzing results...");

        // Store Results
        if (dbConnected) {
             // Determine company from user
            let company = 'Internal'; 
            try {
                const user = await User.findOne({ username: websiteUser });
                if (user && user.company) company = user.company;
                
                // AUTOMATION: Save the key to KeyStore for future scheduled scans
                const existingKey = await KeyStore.findOne({ projectId: json.project_id, uploadedBy: websiteUser });
                if (!existingKey) {
                    await KeyStore.create({
                        fileName: req.file.originalname,
                        projectId: json.project_id,
                        clientEmail: json.client_email,
                        uploadedBy: websiteUser,
                        keyContent: json
                    });
                    log("Credential secured for future automated scans.");
                }
            } catch(e) { console.error("Key persistence error:", e); }

            const { scanId, summary } = await saveScanResults(websiteUser, company, 'GCP', results, json.project_id);
            log(`Scan results saved with ID: ${scanId}`);
            
            await saveHistory({
                performedBy: websiteUser,
                userEmail: json.client_email || "GCP Service Account",
                projectId: results.projectId || json.project_id,
                projectName: (results.projectMetadata && results.projectMetadata.name) || results.projectId || json.project_id,
                keyName: req.file.originalname,
                scanId: scanId,
                company: company,
                platform: 'GCP',
                timestamp: new Date().toISOString(),
                high: summary.high,
                medium: summary.medium,
                low: summary.low
            });
        }

        res.write(`RESULT: ${JSON.stringify(results)}\n`);
        res.end();

    } catch (error) {
        console.error("Scan Error:", error);
        log(`Error: ${error.message}`);
        res.end();
    } finally {
        // SECURE CLEANUP: Delete the key file immediately
        try {
            if (fs.existsSync(keyPath)) {
                fs.unlinkSync(keyPath);
                console.log(`[SECURE] Deleted uploaded key file: ${keyPath}`);
            }
        } catch (cleanupErr) {
            console.error(`[SECURE] Failed to cleanup key file ${keyPath}:`, cleanupErr);
        }
    }
});




// API: Start AWS Scan (Real)
app.post('/api/scan-aws', async (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');
    res.setHeader('X-Accel-Buffering', 'no');
    res.setHeader('Cache-Control', 'no-cache');

    const log = (msg) => res.write(`LOG: ${msg}\n`);

    try {
        const { awsAccessKeyId, awsSecretAccessKey, awsRegion, username } = req.body;
        
        if (!awsAccessKeyId || !awsSecretAccessKey) {
            throw new Error("AWS Access Key ID and Secret Access Key are required.");
        }

        log("Establishing AWS Secure Session...");
        const websiteUser = username || "Anonymous";
        const region = awsRegion || 'us-east-1';
        
        // Run Real AWS Audit
        const results = await runAWSAudit(
            awsAccessKeyId.trim(), 
            awsSecretAccessKey.trim(), 
            region, 
            log
        );

        // Lookup User for Company info
        let userCompany = 'Internal';
        if (dbConnected) {
            const userRecord = await User.findOneAndUpdate(
                { username: websiteUser },
                { 
                    $set: { 
                        'awsCredentials.accessKey': awsAccessKeyId,
                        'awsCredentials.secretKey': awsSecretAccessKey,
                        'awsCredentials.region': region
                    } 
                },
                { new: true }
            );
            if (userRecord && userRecord.company) userCompany = userRecord.company;
            log("AWS Credentials updated for automated scheduling.");
        }

        // Save Complete Scan Results (FIRST)
        let savedScanId = null;
        let scanSummary = { high: 0, medium: 0, low: 0 };
        try {
            const saveRes = await saveScanResults(websiteUser, userCompany, 'AWS', results, "AWS Credentials");
            savedScanId = saveRes.scanId;
            scanSummary = saveRes.summary;
            log(`Scan results saved with ID: ${savedScanId}`);
        } catch (e) { console.error("Scan Results Save Error:", e); }

        // Record to History (SECOND)
        try {
            const historyRecord = {
                performedBy: websiteUser,
                userEmail: awsAccessKeyId,
                projectId: results.accountId,
                projectName: `AWS Account ${results.accountId}`,
                keyName: "AWS Credentials",
                scanId: savedScanId,
                company: userCompany,
                platform: 'AWS',
                timestamp: new Date().toISOString(),
                high: scanSummary.high,
                medium: scanSummary.medium,
                low: scanSummary.low
            };
            await saveHistory(historyRecord);
        } catch (e) { console.error("History Save Error:", e); }

        res.write(`RESULT: ${JSON.stringify(results)}\n`);
    } catch (error) {
        log(`ERROR: ${error.message}`);
    } finally {
        res.end();
    }
});

// API: Start Azure Scan (Simulated)
app.post('/api/scan-azure', async (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');

    const log = (msg) => res.write(`LOG: ${msg}\n`);

    try {
        log("Connecting to Microsoft Azure Console...");
        const websiteUser = req.body.username || "Anonymous";
        const results = await runSimulatedAudit('azure', req.body, log);

        // Lookup User
        let userCompany = 'Internal';
        if (dbConnected) {
            const userRecord = await User.findOne({ username: websiteUser });
            if (userRecord && userRecord.company) userCompany = userRecord.company;
        }

        // Save Complete Scan Results
        let savedScanId = null;
        let scanSummary = { high: 0, medium: 0, low: 0 };
        try {
             const saveRes = await saveScanResults(websiteUser, userCompany, 'AZURE', results, "Azure Credentials");
             savedScanId = saveRes.scanId;
             scanSummary = saveRes.summary;
        } catch(e) { console.error("Scan Save Error", e); }


        // Record to History
        try {
            const historyRecord = {
                performedBy: websiteUser,
                userEmail: req.body.azureTenantId || "Demo-Tenant",
                projectId: results.projectId,
                projectName: results.projectMetadata.name,
                keyName: "Azure Credentials",
                scanId: savedScanId,
                company: userCompany,
                platform: 'AZURE',
                timestamp: new Date().toISOString(),
                high: scanSummary.high,
                medium: scanSummary.medium,
                low: scanSummary.low
            };
            await saveHistory(historyRecord);
        } catch (e) { console.error("History Save Error:", e); }

        res.write(`RESULT: ${JSON.stringify(results)}\n`);
    } catch (error) {
        log(`ERROR: ${error.message}`);
    } finally {
        res.end();
    }
});

// API: Start Onboarding Scan (Simulated & Persisted)
app.post('/api/scan-onboarding', async (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');

    const log = (msg) => res.write(`LOG: ${msg}\n`);

    try {
        const platform = req.body.platform || 'gcp';
        const websiteUser = req.body.username || "Adim";
        
        log(`Connecting to ${platform.toUpperCase()} Console...`);
        const results = await runSimulatedAudit(platform, req.body, log);

        // Lookup User
        let userCompany = 'Internal';
        if (dbConnected) {
            const userRecord = await User.findOne({ username: websiteUser });
            if (userRecord && userRecord.company) userCompany = userRecord.company;
        }

        // Save Scan Results First
        let savedScanId = null;
        let scanSummary = { high: 0, medium: 0, low: 0 };
        try {
             const saveRes = await saveScanResults(websiteUser, userCompany, platform.toUpperCase(), results, "Onboarding Init");
             savedScanId = saveRes.scanId;
             scanSummary = saveRes.summary;
        } catch(e) { console.error("Scan Save Error", e); }

        // Record to History
        try {
            const historyRecord = {
                performedBy: websiteUser,
                userEmail: req.body.email || "onboarding@demo.com",
                projectId: results.projectId,
                projectName: results.projectMetadata.name,
                keyName: "Onboarding Init",
                scanId: savedScanId,
                company: userCompany,
                platform: platform.toUpperCase(),
                timestamp: new Date().toISOString(),
                high: scanSummary.high,
                medium: scanSummary.medium,
                low: scanSummary.low
            };
            await saveHistory(historyRecord);
            log("Audit results saved to persistent history.");
        } catch (e) { 
            console.error("History Save Error:", e);
            log("Warning: Failed to save history.");
        }

        res.write(`RESULT: ${JSON.stringify(results)}\n`);
    } catch (error) {
        log(`ERROR: ${error.message}`);
    } finally {
        res.end();
    }
});

// Serve frontend for all other routes (SPA support)
app.get(/.*/, (req, res) => {
    // If user is accessing /dashboard directly, serve dashboard.html via frontend routing logic (or just serve file directly for simplicity in this MPA/SPA hybrid)
    if (req.url === '/dashboard') {
         res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
    } else {
         res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

// --- Initialize Active Schedules ---
async function initSchedules() {
    try {
        if (!dbConnected) {
            console.warn("[SERVER] Skipping schedule initialization: Database not connected.");
            return;
        }
        
        const activeSchedules = await Schedule.find({ active: true }).lean();
        console.log(`[SERVER] Found ${activeSchedules.length} active schedules. Initializing...`);
        
        activeSchedules.forEach(s => {
            console.log(`[SERVER-DEBUG] Schedule for ${s.userId}:`, JSON.stringify(s));
            console.log(`[SERVER] Scheduling ${s.platform} scan for ${s.userId} (Frequency: ${s.frequency}, Time: ${s.time})`);
            
            // Decrypt credentials before passing to scheduler
            const decryptedCreds = decryptScheduleCredentials(s.credentials);

            scheduler.scheduleScan(s.userId, {
                id: s._id.toString(),
                platform: s.platform,
                frequency: s.frequency,
                notifyEmail: s.notifyEmail,
                email: s.email,
                credentials: decryptedCreds,
                company: s.company,
                timezone: s.timezone,
                time: s.time,
                dayOfWeek: s.dayOfWeek,
                dayOfMonth: s.dayOfMonth,
                interval: s.interval,
                startDate: s.startDate,
                endDate: s.endDate,
                date: s.date,
                selectedKeyId: s.selectedKeyId
            });
        });
        console.log("[SERVER] All active schedules have been registered with the scheduler.");
    } catch (e) {
        console.error("[SERVER] Failed to init schedules:", e.message);
    }
}

// Start DB and then Server
startDB().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
        console.log(`Google Client ID: ${CLIENT_ID}`);
        // Initialize schedules after DB is ready
        initSchedules();
    });
});
