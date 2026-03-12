const mongoose = require('mongoose');

async function deleteUsers() {
    try {
        const MONGODB_URI = 'mongodb://127.0.0.1:27017/gcp-audit';
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to Database.');

        const emailsToDelete = ['ratanshakya999@gmail.com', 'ratanshakya9557@gmail.com'];
        
        // Define a minimal User model to perform deletion
        const User = mongoose.model('User', new mongoose.Schema({ email: String }, { strict: false }));

        const result = await User.deleteMany({ email: { $in: emailsToDelete } });
        console.log(`Successfully deleted ${result.deletedCount} users.`);
        
        // Also check by username just in case they were stored without email field but with username matching prefix
        const usernamesToDelete = emailsToDelete.map(e => e.split('@')[0]);
        const resultByUsername = await User.deleteMany({ username: { $in: usernamesToDelete } });
        console.log(`Successfully deleted ${resultByUsername.deletedCount} users by username mapping.`);

    } catch (e) {
        console.error('Error during deletion:', e.message);
    } finally {
        await mongoose.disconnect();
        process.exit(0);
    }
}

deleteUsers();
