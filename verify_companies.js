const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

// Simplified Schema matching server.js
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    displayName: String,
    company: String,
    role: String,
    picture: String,
    joinedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

async function checkUsers() {
    // We need to connect to the *running* instance if possible, 
    // but without the connection string it's hard.
    // HOWEVER, the user is running `server.js` which uses `mongodb-memory-server`.
    // We cannot connect to that in-memory instance from a separate process easily 
    // unless we know the port/uri it picked.
    
    // STARTING STRATEGY: 
    // Inspect the output of the running server to find the MongoDB URI.
    // The previous tool output showed: "MongoDB Memory Server started at mongodb://127.0.0.1:45733/"
    
    // I will try to connect to THAT URI.
    // Note: The port changes on every restart. 
    // I need to use the MOST RECENT one from the logs.
    
    const uri = "mongodb://127.0.0.1:45733/"; // From previous turn's output
    
    try {
        await mongoose.connect(uri);
        console.log("Connected to MongoDB at " + uri);
        
        const users = await User.find({});
        console.log("\n--- USER DATABASE DUMP ---");
        users.forEach(u => {
            console.log(`User: ${u.username} | Company: '${u.company}' | Email: ${u.email}`);
        });
        console.log("--------------------------\n");
        
    } catch (e) {
        console.error("Connection failed:", e);
    } finally {
        await mongoose.disconnect();
    }
}

checkUsers();
