const mongoose = require('mongoose');

async function checkUsers() {
    try {
        const MONGODB_URI = 'mongodb://127.0.0.1:27017/gcp-audit';
        await mongoose.connect(MONGODB_URI);
        const User = mongoose.model('User', new mongoose.Schema({}, { strict: false }));
        const users = await User.find({});
        console.log('Current users in DB:', users.map(u => ({ username: u.username, email: u.email })));
    } catch (e) {
        console.error(e);
    } finally {
        await mongoose.disconnect();
        process.exit(0);
    }
}

checkUsers();
