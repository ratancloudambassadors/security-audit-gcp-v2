// EMERGENCY FIX: Force reload scan data
// Paste this into browser console to manually load your latest scan

(async function() {
    console.log('🔧 EMERGENCY RELOAD STARTED');
    
    try {
        // Get user
        const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
        if (!user) {
            console.error('❌ No user found in localStorage');
            alert('Please login first');
            return;
        }
        
        const username = user.email || user.username || user.name;
        console.log('👤 User:', username);
        
        // Fetch latest scan
        const url = `/api/scan-results/latest?userId=${encodeURIComponent(username)}&platform=GCP`;
        console.log('🌐 Fetching:', url);
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (!data.success || !data.scan) {
            console.error('❌ No scan found');
            alert('No scan data found for user: ' + username);
            return;
        }
        
        console.log('✅ Scan found:', data.scan.scanId);
        console.log('📊 Summary:', data.scan.summary);
        
        // Check if processResults exists
        if (typeof processResults !== 'function') {
            console.error('❌ processResults function not found!');
            alert('ERROR: processResults function not available. Page may not be fully loaded.');
            return;
        }
        
        // Load the scan
        console.log('🔄 Loading scan results...');
        processResults(data.scan.results);
        
        // Switch to inventory tab
        if (typeof switchTab === 'function') {
            setTimeout(() => switchTab('inventory'), 300);
        }
        
        // Show indicator
        const scanDate = new Date(data.scan.timestamp).toLocaleString();
        const indicator = document.createElement('div');
        indicator.id = 'previous-scan-indicator';
        indicator.style.cssText = `
            position: fixed;
            top: 70px;
            right: 20px;
            background: linear-gradient(135deg, var(--cc-primary) 0%, #059669 100%);
            color: #05070a;
            padding: 12px 20px;
            border-radius: 12px;
            box-shadow: 0 4px 15px var(--cc-primary-glow);
            z-index: 1000;
            font-size: 0.85rem;
            font-weight: 800;
            border: none;
        `;
        indicator.innerHTML = `
            📊 Viewing Previous Scan<br>
            <span style="font-size: 0.75rem; opacity: 0.9;">${scanDate}</span>
        `;
        
        // Remove old indicator if exists
        const old = document.getElementById('previous-scan-indicator');
        if (old) old.remove();
        
        document.body.appendChild(indicator);
        
        console.log('✅ SCAN LOADED SUCCESSFULLY!');
        alert('✅ Scan loaded! Check Inventory tab.');
        
    } catch (e) {
        console.error('❌ ERROR:', e);
        alert('Error: ' + e.message);
    }
})();
