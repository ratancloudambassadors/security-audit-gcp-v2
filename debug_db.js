require('dotenv').config();
const mongoose = require('mongoose');

const scanResultsSchema = new mongoose.Schema({
    scanId: String,
    platform: String,
    projectId: String,
    timestamp: Date,
    userId: String,
    company: String
});

const ScanResults = mongoose.model('ScanResults', scanResultsSchema);

async function check() {
    try {
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/gcp-audit');
        console.log('Connected to DB');
        const latest = await ScanResults.find().sort({ timestamp: -1 }).limit(5);
        console.log('Latest 5 Scans:');
        latest.forEach(s => {
            console.log(`ID: ${s.scanId}, Platform: ${s.platform}, Project: ${s.projectId}, User: ${s.userId}, Company: ${s.company}, Time: ${s.timestamp}`);
        });
        process.exit(0);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

check();
