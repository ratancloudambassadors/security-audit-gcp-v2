const mongoose = require('mongoose');
const UserSchema = new mongoose.Schema({
    username: String,
    displayName: String,
    email: String,
    role: String,
    company: String
}, { strict: false });
const User = mongoose.model('User', UserSchema);

async function dump() {
    try {
        await mongoose.connect('mongodb://localhost:27017/gcp_audit');
        const users = await User.find({});
        console.log(JSON.stringify(users, null, 2));
    } catch (e) {
        console.error(e);
    } finally {
        process.exit(0);
    }
}
dump();
