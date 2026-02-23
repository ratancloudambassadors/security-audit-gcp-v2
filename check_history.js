const mongoose = require('mongoose');

// Schema for History
const scanHistorySchema = new mongoose.Schema({
    timestamp: Date,
    platform: String,
    performedBy: String,
    summary: Object
}, { strict: false });
const ScanHistory = mongoose.model('ScanHistory', scanHistorySchema);

async function check() {
    try {
        await mongoose.connect('mongodb://127.0.0.1:27017/gcp-audit');
        const history = await ScanHistory.find({}).sort({ timestamp: -1 }).limit(5);
        console.log("Recent History:");
        history.forEach(h => {
            console.log(`- Time: ${h.timestamp.toISOString()}, Platform: ${h.platform}, By: ${h.performedBy}`);
        });
        process.exit(0);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}
check();
