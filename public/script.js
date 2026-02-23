document.addEventListener('DOMContentLoaded', () => {

// --- Toast Utilities ---
window.showToast = function(message, type = 'success', title = 'Notification', duration = 3000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    // container.innerHTML = ''; // Optional: Clear previous if needed
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let iconName = 'notifications-outline';
    if (type === 'success') iconName = 'checkmark-circle-outline';
    if (type === 'error') iconName = 'alert-circle-outline';
    if (type === 'warning') iconName = 'warning-outline';

    toast.innerHTML = `
        <div class="toast-icon"><ion-icon name="${iconName}"></ion-icon></div>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
        <div class="toast-progress">
            <div class="toast-progress-bar" id="progress-${Date.now()}"></div>
        </div>
    `;

    container.appendChild(toast);
    const progressBar = toast.querySelector('.toast-progress-bar');
    
    setTimeout(() => {
        toast.classList.add('show');
        progressBar.style.transitionDuration = `${duration}ms`;
        progressBar.style.width = '0%';
    }, 10);

    setTimeout(() => {
        if (toast.parentNode) {
            toast.classList.remove('show');
            setTimeout(() => { if (toast.parentNode) toast.remove(); }, 500);
        }
    }, duration);
};

    
    // Navbar scroll effect
    window.addEventListener('scroll', () => {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // Check if user is logged in
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    const isLoginPage = window.location.pathname.endsWith('login.html');

    if (user) {
        if (isLoginPage) {
            window.location.href = '/';
            return;
        }
        updateUIForLoggedInUser(user);
    } else {
        // If not logged in and not on login page, redirect (optional, but good for "protected" apps)
        // For this landing page, we only redirect if they try to click "Launch Console"
    }

    // --- Navigation & Interactivity ---
    
    // Smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if(target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    const startBtn = document.getElementById('start-audit-btn');
    const launchBtn = document.getElementById('launch-app');
    const mockLoginBtn = document.getElementById('mock-login-btn');

    if (startBtn) {
        startBtn.addEventListener('click', () => {
            if (!user) {
                window.location.href = 'login.html';
            } else {
                startAudit();
            }
        });
    }

    if (launchBtn) {
        launchBtn.addEventListener('click', (e) => {
            e.preventDefault(); // Prevent default anchor behavior if it's an <a> tag
            if (!user) {
                window.location.href = 'login.html';
            } else {
                window.location.href = 'dashboard.html';
            }
        });
    }

    const manualLoginForm = document.getElementById('manual-login-form');
    if (manualLoginForm) {
        manualLoginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (data.success) {
                    localStorage.setItem('gcp_audit_user', JSON.stringify(data.user));
                    localStorage.setItem('gcp_audit_token', data.token);
                    window.location.href = 'dashboard.html';
                    localStorage.setItem('gcp_audit_token', data.token);
                    window.location.href = 'dashboard.html';
                } else {
                    showToast(data.message || 'Login failed', 'error', 'Access Denied');
                }
            } catch (err) {
                console.error(err);
                showToast('An error occurred. Check connection.', 'error', 'System Error');
            }
        });
    }

    const showRegister = document.getElementById('show-register'); // Legacy generic button
    
    // New Signup Flow Logic
    const signupForm = document.getElementById('signup-form');
    const showSignupLink = document.getElementById('show-signup-link');
    const showLoginLink = document.getElementById('show-login-link');
    const loginHeader = document.querySelector('.login-header h2');
    const loginSubHeader = document.querySelector('.login-header p');

    if (showSignupLink && signupForm && manualLoginForm) {
        showSignupLink.addEventListener('click', (e) => {
            e.preventDefault();
            manualLoginForm.style.display = 'none';
            signupForm.style.display = 'block';
            loginHeader.innerText = "Join the Team";
            loginSubHeader.innerText = "Create your secure auditor profile";
        });

        showLoginLink.addEventListener('click', (e) => {
            e.preventDefault();
            signupForm.style.display = 'none';
            manualLoginForm.style.display = 'block';
            loginHeader.innerText = "Secure Access";
            loginSubHeader.innerText = "Enter your credentials to manage cloud infrastructure";
        });

        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('reg-username').value;
            const password = document.getElementById('reg-password').value;
            const displayName = document.getElementById('reg-displayname').value;
            const company = document.getElementById('reg-company').value;
            
            if(username && password) {
                registerWithBackend(username, password, displayName, company);
            }
        });
    }

    if (showRegister) {
        showRegister.addEventListener('click', (e) => {
            e.preventDefault();
            const newUsername = prompt("Choose a username:");
            const newPassword = prompt("Choose a password:");
            const displayName = prompt("Your Name:");
            const company = prompt("Company Name:");
            if (newUsername && newPassword) {
                registerWithBackend(newUsername, newPassword, displayName, company);
            }
        });
    }

    if (mockLoginBtn) {
        mockLoginBtn.addEventListener('click', () => {
            loginWithBackend('mock-token');
        });
    }

    // --- Animation Simulation ---
    const codeBlock = document.querySelector('.code-block');
    if (codeBlock) {
        const lines = [
            { type: 'prompt', text: '$ gcp-audit --target-project production-main' },
            { type: 'success', text: '✓ Authentication Verified: Organization Admin' },
            { type: 'info', text: 'i Crawling 42 Active Services...' },
            { type: 'info', text: 'i Mapping VPC Network Topology...' },
            { type: 'warning', text: '! Critical: Open SSH Port 22 in \'web-tier-firewall\'' },
            { type: 'loading', text: 'Finalizing Compliance Report_' }
        ];

        let lineIndex = 0;
        
        function typeWriter(text, element, i, callback) {
            if (i < text.length) {
                element.innerHTML += text.charAt(i);
                setTimeout(() => typeWriter(text, element, i + 1, callback), 30); // Typing speed
            } else if (callback) {
                callback();
            }
        }

        function runAnimation() {
            codeBlock.innerHTML = ''; // Clear existing
            lineIndex = 0;
            processNextLine();
        }

        function processNextLine() {
            if (lineIndex < lines.length) {
                const lineData = lines[lineIndex];
                const div = document.createElement('div');
                div.className = 'line';
                
                if (lineData.type === 'loading') {
                    div.className += ' loading';
                    div.innerHTML = lineData.text.slice(0, -1) + '<span class="cursor">_</span>';
                    codeBlock.appendChild(div);
                    // End of loop for now, maybe restart?
                    setTimeout(runAnimation, 5000); 
                } else {
                    // Create span for icon/prompt
                    let prefix = '';
                    if (lineData.type === 'prompt') prefix = '<span class="prompt">></span> ';
                    else if (lineData.type === 'success') prefix = '<span class="success">✓</span> ';
                    else if (lineData.type === 'info') prefix = '<span class="info">i</span> ';
                    else if (lineData.type === 'warning') prefix = '<span class="warning">!</span> ';
                    
                    div.innerHTML = prefix;
                    codeBlock.appendChild(div);
                    
                    // Type the text content
                    const textSpan = document.createElement('span');
                    if (lineData.type === 'prompt') textSpan.className = 'cmd'; // specific style for command
                    div.appendChild(textSpan);
                    
                    const textToType = lineData.text.replace(/^[>✓i!] /, ''); // Remove prefix chars from typing source
                    
                    typeWriter(textToType, textSpan, 0, () => {
                        lineIndex++;
                        setTimeout(processNextLine, 500);
                    });
                }
            }
        }

        // Start animation
        runAnimation();
    }
});

async function registerWithBackend(username, password, displayName, company) {
    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, displayName, company })
        });
        const data = await response.json();
        if (data.success) {
            // Clear any stale setup state for this username in case of re-registration
            localStorage.removeItem(`gcp_audit_setup_complete_${username}`);
            
            showToast('Registration successful! Please login.', 'success', 'Welcome');
            setTimeout(() => {
                document.getElementById('show-login-link').click(); // Auto switch to login
            }, 1000);
        } else {
             showToast('Registration failed: ' + data.message, 'error', 'Error');
        }
    } catch (err) {
        console.error(err);
        showToast('An error occurred during registration.', 'error', 'System Error');
    }
}

async function loginWithBackend(token) {
    try {
        const response = await fetch('/api/auth/google', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });
        
        const data = await response.json();
        
        if (data.success) {
            localStorage.setItem('gcp_audit_user', JSON.stringify(data.user));
            localStorage.setItem('gcp_audit_token', data.token);
            window.location.href = 'dashboard.html';
            localStorage.setItem('gcp_audit_token', data.token);
            window.location.href = 'dashboard.html';
        } else {
            showToast('Login failed: ' + data.message, 'error', 'Access Denied');
        }
    } catch (error) {
        console.error('Login Error:', error);
        showToast('An error occurred during login.', 'error', 'System Error');
    }
}

function updateUIForLoggedInUser(user) {
    const navLinks = document.querySelector('.nav-links');
    const launchBtn = document.getElementById('launch-app');
    
    // Replace "Launch Console" with User Profile
    if (launchBtn && launchBtn.parentElement) {
        const profileDiv = document.createElement('div');
        profileDiv.className = 'user-profile glass';
        profileDiv.style.padding = '5px 15px';
        profileDiv.style.borderRadius = '30px';
        profileDiv.style.cursor = 'pointer';
        profileDiv.innerHTML = `
            <img src="${user.picture}" alt="User">
            <span>${user.name.split(' ')[0]}</span>
        `;
        
        profileDiv.addEventListener('click', () => {
            if(confirm('Logout?')) {
                localStorage.removeItem('gcp_audit_user');
                localStorage.removeItem('gcp_audit_token');
                window.location.reload();
            }
        });

        launchBtn.replaceWith(profileDiv);
    }
}

function startAudit() {
    window.location.href = 'dashboard.html';
}

// --- Automation Tab Logic ---

let autoConfig = {
    platform: 'GCP',
    frequency: 'daily',
    time: '09:00',
    days: [1], // Monday default
    dom: 1,
    notify: true
};

function selectAutoPlatform(platform, el) {
    autoConfig.platform = platform;
    document.getElementById('auto-platform').value = platform;
    
    // Update UI
    document.querySelectorAll('#automation-form .cloud-option').forEach(opt => {
        opt.classList.remove('selected');
        opt.style.borderColor = 'rgba(255, 255, 255, 0.1)';
        opt.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
    });
    
    el.classList.add('selected');
    el.style.borderColor = 'var(--primary)';
    el.style.backgroundColor = 'rgba(26, 115, 232, 0.1)';
    
    // Load existing schedule for this platform
    loadSchedule(platform);
}

async function loadAvailableKeys(platform) {
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (!user) return;
    
    const keySelect = document.getElementById('auto-key-select');
    if (!keySelect) return;

    try {
        const userId = user.email || user.username;
        const response = await fetch(`/api/user/keys?userId=${encodeURIComponent(userId)}&platform=${platform}`);
        const data = await response.json();
        
        if (data.success) {
            // Keep the first "Auto-detected" option
            keySelect.innerHTML = '<option value="">Auto-detected (Default)</option>';
            
            data.keys.forEach(key => {
                const opt = document.createElement('option');
                opt.value = key._id;
                // Show projectName if available, else fileName
                const label = key.projectId ? `${key.projectId} (${key.fileName})` : key.fileName;
                opt.innerText = label;
                keySelect.appendChild(opt);
            });
            
            // Show/hide group based on if platform is GCP (currently only GCP uses KeyStore)
            document.getElementById('auto-key-group').style.display = platform === 'GCP' ? 'block' : 'none';
        }
    } catch (e) {
        console.error('Error loading keys:', e);
    }
}

async function uploadAutomationKey(input) {
    if (!input.files || !input.files[0]) return;
    
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (!user) return showToast('Please login first', 'error');

    const file = input.files[0];
    const formData = new FormData();
    formData.append('keyFile', file);
    formData.append('username', user.email || user.username);

    showToast('Uploading service account key...', 'info');

    try {
        const response = await fetch('/api/user/keys/upload', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('Key uploaded successfully', 'success');
            // Reset input
            input.value = '';
            // Refresh keys list
            const platform = document.getElementById('auto-platform').value;
            loadAvailableKeys(platform);
        } else {
            showToast('Upload failed: ' + data.message, 'error');
        }
    } catch (e) {
        console.error('Upload error:', e);
        showToast('Connection error during upload', 'error');
    }
}

function toggleDayInputs() {
    const freq = document.getElementById('auto-frequency').value;
    const dayRow = document.getElementById('day-row');
    const dowGroup = document.getElementById('dow-group');
    const domGroup = document.getElementById('dom-group');
    
    autoConfig.frequency = freq;

    if (freq === 'daily') {
        dayRow.style.display = 'none';
        document.getElementById('date-group').style.display = 'none';
    } else if (freq === 'weekly') {
        dayRow.style.display = 'flex';
        dowGroup.style.display = 'block';
        domGroup.style.display = 'none';
        document.getElementById('date-group').style.display = 'none';
    } else if (freq === 'monthly') {
        dayRow.style.display = 'flex';
        dowGroup.style.display = 'none';
        domGroup.style.display = 'block';
        document.getElementById('date-group').style.display = 'none';
    } else if (freq === 'once') {
        dayRow.style.display = 'none';
        document.getElementById('date-group').style.display = 'block';
    }
    
    calculateNextScan();
}

function selectDay(dayIndex, el) {
    // Toggle selection
    if (el.classList.contains('active')) {
         // Prevent deselecting the only day
         if (autoConfig.days.length > 1) {
            el.classList.remove('active');
            autoConfig.days = autoConfig.days.filter(d => d !== dayIndex);
         }
    } else {
        el.classList.add('active');
        autoConfig.days.push(dayIndex);
    }
    document.getElementById('auto-dow').value = autoConfig.days.join(',');
    calculateNextScan();
}

async function saveSchedule() {
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (!user) return showToast('Please login first', 'error');

    const config = {
        userId: user.email || user.username,
        platform: document.getElementById('auto-platform').value,
        frequency: document.getElementById('auto-frequency').value,

        time: (() => {
            const h = document.getElementById('auto-time-hour').value;
            const m = document.getElementById('auto-time-minute').value;
            const p = document.getElementById('auto-time-ampm').value;
            let hour = parseInt(h, 10);
            if (p === 'PM' && hour !== 12) hour += 12;
            if (p === 'AM' && hour === 12) hour = 0;
            return `${hour.toString().padStart(2, '0')}:${m}`;
        })(),
        dayOfWeek: document.getElementById('auto-dow').value,

        dayOfMonth: document.getElementById('auto-dom').value,
        date: document.getElementById('auto-date').value,
        notifyEmail: document.getElementById('auto-notify').checked,
        email: document.getElementById('auto-email').value,
        active: document.getElementById('auto-active').checked,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        selectedKeyId: document.getElementById('auto-key-select').value || null
    };

    try {
        const response = await fetch('/api/user/schedule', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('Schedule saved successfully', 'success');
            calculateNextScan();
            updateHistoryLog('Schedule updated', 'success');
        } else {
            showToast('Failed to save: ' + data.message, 'error');
        }
    } catch (e) {
        showToast('Error saving schedule', 'error');
        console.error(e);
    }
}

async function loadSchedule(platform) {
   const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
   if (!user) return;

   const userId = user.email || user.username;
   
   // First load available keys
   await loadAvailableKeys(platform);

   try {
       const response = await fetch(`/api/user/schedule?userId=${encodeURIComponent(userId)}&platform=${platform}`);
       const data = await response.json();
       
       if (data.success && data.schedule) {
           const s = data.schedule;
           document.getElementById('auto-frequency').value = s.frequency || 'once';
           
           if (s.time) {
               const [h, m] = s.time.split(':');
               let hour = parseInt(h, 10);
               let ampm = 'AM';
               if (hour >= 12) {
                   ampm = 'PM';
                   if (hour > 12) hour -= 12;
               }
               if (hour === 0) hour = 12;
               
               document.getElementById('auto-time-hour').value = hour.toString().padStart(2, '0');
               document.getElementById('auto-time-minute').value = m;
               document.getElementById('auto-time-ampm').value = ampm;
           }

           if (s.dayOfWeek) {
               const days = s.dayOfWeek.split(',').map(Number);
               autoConfig.days = days;
               document.querySelectorAll('.day-selector .day-btn').forEach((btn, idx) => {
                   if (days.includes(idx)) btn.classList.add('active');
                   else btn.classList.remove('active');
               });
           }

           if (s.dayOfMonth) document.getElementById('auto-dom').value = s.dayOfMonth;
           if (s.date) document.getElementById('auto-date').value = s.date.split('T')[0];
           
           document.getElementById('auto-notify').checked = s.notifyEmail !== false;
           if (s.email) document.getElementById('auto-email').value = s.email;
           document.getElementById('auto-active').checked = s.active !== false;
           
           if (s.selectedKeyId) {
               document.getElementById('auto-key-select').value = s.selectedKeyId;
           }

           toggleDayInputs();
           calculateNextScan();
       } else {
            // Reset to defaults if no schedule found
            document.getElementById('auto-frequency').value = 'once';
            document.getElementById('auto-date').value = '';
            document.getElementById('auto-time-hour').value = '09';
            document.getElementById('auto-time-minute').value = '00';
            document.getElementById('auto-time-ampm').value = 'AM';
            document.getElementById('auto-active').checked = true;
            toggleDayInputs();
            calculateNextScan();
       }
   } catch(e) {
       console.error('Error loading schedule:', e);
   }
}

async function runManualTest() {
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    const platform = document.getElementById('auto-platform').value;
    
    showToast(`Triggering manual ${platform} scan...`, 'info');
    
    try {
        const response = await fetch('/api/user/schedule/test', {
             method: 'POST',
             headers: { 'Content-Type': 'application/json' },
             body: JSON.stringify({
                 userId: user.email || user.username,
                 platform: platform,
                 notifyEmail: document.getElementById('auto-notify').checked,
                 email: document.getElementById('auto-email').value,
                 selectedKeyId: document.getElementById('auto-key-select').value || null
             })
        });
        
        const data = await response.json();
        if (data.success) {
            showToast('Scan initiated successfully', 'success');
            updateHistoryLog(`Manual scan started (${platform})`, 'success');
        } else {
            showToast('Failed to start scan', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

function calculateNextScan() {
    const active = document.getElementById('auto-active').checked;
    const nextScanEl = document.getElementById('next-scan-time');
    const statusTextEl = document.querySelector('.nav-status .status-text');
    const statusDotEl = document.querySelector('.nav-status .status-dot');

    if (!active) {
        if (nextScanEl) nextScanEl.innerText = 'Disabled';
        if (statusTextEl) statusTextEl.innerText = 'OFFLINE';
        if (statusDotEl) statusDotEl.style.background = '#666';
        return;
    }

    const freq = document.getElementById('auto-frequency').value;
    const hStr = document.getElementById('auto-time-hour').value;
    const mStr = document.getElementById('auto-time-minute').value;
    const ampm = document.getElementById('auto-time-ampm').value;
    
    let h = parseInt(hStr, 10);
    if (ampm === 'PM' && h !== 12) h += 12;
    if (ampm === 'AM' && h === 12) h = 0;

    const now = new Date();
    let next = new Date();
    next.setHours(h, parseInt(mStr, 10), 0, 0);

    let isPast = false;

    if (freq === 'once') {
        const dateInput = document.getElementById('auto-date').value;
        if (dateInput) {
            const [y, m, d] = dateInput.split('-').map(Number);
            next.setFullYear(y, m - 1, d);
            if (next <= now) isPast = true;
        } else {
            if (nextScanEl) nextScanEl.innerText = 'Select Date';
            return;
        }
    } else {
        // For recurring, if the time today already passed, move to tomorrow
        if (next <= now) {
            next.setDate(next.getDate() + 1);
        }
        
        if (freq === 'weekly') {
            const selectedDow = parseInt(document.getElementById('auto-dow').value, 10);
            while (next.getDay() !== selectedDow) {
                next.setDate(next.getDate() + 1);
            }
        } else if (freq === 'monthly') {
            const selectedDom = parseInt(document.getElementById('auto-dom').value, 10);
            next.setDate(selectedDom);
            if (next <= now) {
                next.setMonth(next.getMonth() + 1);
            }
        }
    }
    
    if (nextScanEl) {
        if (isPast) {
            nextScanEl.innerText = 'Time is in the past';
            nextScanEl.style.color = 'var(--danger)';
        } else {
            nextScanEl.innerText = next.toLocaleString([], {
                weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
            });
            nextScanEl.style.color = ''; // Reset color
        }
    }
    
    if (statusTextEl) statusTextEl.innerText = 'ONLINE';
    if (statusDotEl) statusDotEl.style.background = '#00d084';
}

function updateHistoryLog(msg, type) {
    const list = document.getElementById('auto-history-list');
    const item = document.createElement('div');
    item.style.display = 'flex';
    item.style.justifyContent = 'space-between';
    item.style.color = type === 'success' ? 'var(--success)' : 'var(--text-secondary)';
    item.innerHTML = `<span>${msg}</span><span>${new Date().toLocaleTimeString()}</span>`;
    
    if (list.children[0]?.innerText.includes('No recent')) list.innerHTML = '';
    list.prepend(item);
}

// Init
function populateMinutes() {
    const minSelect = document.getElementById('auto-time-minute');
    if (!minSelect) return;
    minSelect.innerHTML = '';
    for (let i = 0; i < 60; i++) {
        const val = i.toString().padStart(2, '0');
        const opt = document.createElement('option');
        opt.value = val;
        opt.innerText = val;
        if (i === 0) opt.selected = true;
        minSelect.appendChild(opt);
    }
}

setTimeout(() => {
    populateMinutes();
    // Set default email if logged in
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (user && user.email) {
        const emailInput = document.getElementById('auto-email');
        if (emailInput && !emailInput.value) emailInput.value = user.email;
    }
}, 1000);
