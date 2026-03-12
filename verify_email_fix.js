const fetch = require('node-fetch');

async function verifyFix() {
    console.log('--- Email Fix Verification ---');
    
    const payload = {
        userId: 'ratan.shakya@cloudambassadors.com',
        platform: 'GCP',
        notifyEmail: true,
        email: 'ratan.shakya@cloudambassadors.com'
    };

    console.log('Triggering manual scan via API...');
    try {
        const response = await fetch('http://localhost:8080/api/user/schedule/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        console.log('Response:', JSON.stringify(data, null, 2));
        
        if (data.success) {
            console.log('\nSUCCESS: Scan triggered. Please check server logs for "[SCHEDULER_DEBUG] Email sent successfully."');
        } else {
            console.log('\nFAILED:', data.message);
        }
    } catch (err) {
        console.error('Error connecting to server:', err.message);
        console.log('Check if server is running on port 8080.');
    }
}

verifyFix();
