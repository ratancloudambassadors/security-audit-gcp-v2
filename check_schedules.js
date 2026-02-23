const mongoose = require('mongoose');

// Standalone script to check schedules
const scheduleSchema = new mongoose.Schema({
    userId: { type: String },
    platform: { type: String },
    frequency: { type: String },
    time: { type: String },
    active: { type: Boolean },
    notifyEmail: { type: Boolean },
    email: String
}, { strict: false }); // Allow loose schema

const Schedule = mongoose.model('Schedule', scheduleSchema);

async function check() {
    try {
        await mongoose.connect('mongodb://127.0.0.1:27017/gcp-audit');
        console.log("Connected to DB.");
        const schedules = await Schedule.find({});
        console.log(`Found ${schedules.length} schedules.`);
        schedules.forEach(s => {
            console.log(`- User: ${s.userId}, Platform: ${s.platform}, Active: ${s.active}, Time: ${s.time}, Freq: ${s.frequency}, Email: ${s.email || 'N/A'}, Notify: ${s.notifyEmail}, Timezone: ${s.timezone}`);
        });
        process.exit(0);
    } catch (e) {
        console.error("Error:", e);
        process.exit(1);
    }
}
check();
