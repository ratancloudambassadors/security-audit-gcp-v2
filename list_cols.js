const mongoose = require('mongoose');

async function listCollections() {
    try {
        const MONGODB_URI = 'mongodb://127.0.0.1:27017/gcp-audit';
        await mongoose.connect(MONGODB_URI);
        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log('Collections:', collections.map(c => c.name));
    } catch (e) {
        console.error(e);
    } finally {
        await mongoose.disconnect();
        process.exit(0);
    }
}

listCollections();
