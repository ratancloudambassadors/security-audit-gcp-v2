const mongoose = require('mongoose');

async function cleanDatabase() {
    try {
        const MONGODB_URI = 'mongodb://127.0.0.1:27017/gcp-audit';
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to Database. Starting deep clean...');

        const collections = ['users', 'keystores', 'scanhistories', 'schedules', 'scanresults'];
        
        for (const colName of collections) {
            try {
                const count = await mongoose.connection.db.collection(colName).countDocuments();
                await mongoose.connection.db.collection(colName).deleteMany({});
                console.log(`- Cleaned collection '${colName}': ${count} records deleted.`);
            } catch (err) {
                console.log(`- Skipping '${colName}': ${err.message}`);
            }
        }

        console.log('\n✅ Database is now completely clean of operational data.');

    } catch (e) {
        console.error('Error during cleanup:', e.message);
    } finally {
        await mongoose.disconnect();
        process.exit(0);
    }
}

cleanDatabase();
