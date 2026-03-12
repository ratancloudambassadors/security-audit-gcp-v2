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
    const API_BASE_URL = window.location.hostname === 'localhost' ? 'http://localhost:8080/api' : '/api';

// Global Custom Confirm Utility
window.showConfirm = function(title, message, isDanger = false) {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-title');
        const messageEl = document.getElementById('confirm-message');
        const okBtn = document.getElementById('confirm-ok');
        const cancelBtn = document.getElementById('confirm-cancel');

        titleEl.innerHTML = `<ion-icon name="${isDanger ? 'alert-circle' : 'help-circle'}-outline" style="color: ${isDanger ? '#ef4444' : 'var(--primary)'}; font-size: 1.5rem;"></ion-icon><span>${title}</span>`;
        messageEl.textContent = message;
        
        okBtn.className = `confirm-btn confirm ${isDanger ? 'danger' : ''}`;
        
        const cleanup = (result) => {
            modal.classList.add('hidden');
            okBtn.removeEventListener('click', onOk);
            cancelBtn.removeEventListener('click', onCancel);
            resolve(result);
        };

        const onOk = () => cleanup(true);
        const onCancel = () => cleanup(false);

        okBtn.addEventListener('click', onOk);
        cancelBtn.addEventListener('click', onCancel);

        modal.classList.remove('hidden');
    });
};

let currentSchedules = [];
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
        
        profileDiv.addEventListener('click', async (e) => {
            e.stopPropagation();
            if(await showConfirm('Log Out', 'Are you sure you want to log out of your security session?', true)) {
                localStorage.removeItem('gcp_audit_user');
                localStorage.removeItem('gcp_audit_token');
                window.location.href = 'login.html';
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
    notify: true,
    emails: [] // Store added email tags
};

function selectAutoPlatform(platform, el, triggerLoad = true) {
    autoConfig.platform = platform;
    document.getElementById('auto-platform').value = platform;
    
    // Update UI
    document.querySelectorAll('#automation-form .cloud-option').forEach(opt => {
        opt.classList.remove('selected');
        opt.style.borderColor = 'rgba(255, 255, 255, 0.1)';
        opt.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
    });
    
    el.classList.add('selected');
    el.style.borderColor = 'var(--cc-primary)';
    el.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';

    // Toggle credential sections based on platform
    const gcpKeyGroup = document.getElementById('auto-key-group');
    const awsCredsGroup = document.getElementById('auto-aws-creds-group');
    if (gcpKeyGroup) gcpKeyGroup.style.display = platform === 'GCP' ? 'block' : 'none';
    if (awsCredsGroup) awsCredsGroup.style.display = platform === 'AWS' ? 'block' : 'none';

    // For AWS: auto-load saved credentials from profile
    if (platform === 'AWS') loadSavedAwsCredentials();
    
    // Load existing schedule for this platform
    if (triggerLoad) {
        loadSchedule(platform);
    } else {
        autoConfig.emails = []; // Clear current emails for new schedule
        renderEmailTags();
        loadAvailableKeys(platform);
    }
}

// Fetch saved AWS credentials from server (masked) and update the UI
async function loadSavedAwsCredentials() {
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (!user) return;
    const userId = user.email || user.username;

    const savedCard = document.getElementById('aws-saved-card');
    const newForm   = document.getElementById('aws-new-creds-form');
    const changeBtn = document.getElementById('aws-cred-change-btn');

    try {
        const res  = await fetch(`/api/user/aws-credentials?userId=${encodeURIComponent(userId)}`);
        const data = await res.json();

        if (data.success && data.hasSaved) {
            // Show saved card, hide input form
            document.getElementById('aws-saved-masked').innerText = `Key ID: ${data.maskedKey}  |  Region: ${data.region}`;
            savedCard.style.display = 'block';
            newForm.style.display   = 'none';
            changeBtn.style.display = 'flex';
            // Clear input fields since we'll use saved creds
            document.getElementById('auto-aws-key-id').value    = '';
            document.getElementById('auto-aws-secret-key').value = '';
        } else {
            // No saved creds — show the entry form
            savedCard.style.display = 'none';
            newForm.style.display   = 'flex';
            changeBtn.style.display = 'none';
        }
    } catch (e) {
        // On error, default to showing the form
        if (savedCard) savedCard.style.display = 'none';
        if (newForm)   newForm.style.display   = 'flex';
    }
}

// Toggle between saved-card view and new-entry form
function toggleAwsCredMode() {
    const savedCard = document.getElementById('aws-saved-card');
    const newForm   = document.getElementById('aws-new-creds-form');
    const changeBtn = document.getElementById('aws-cred-change-btn');
    if (savedCard.style.display !== 'none') {
        // Switch to entry form
        savedCard.style.display = 'none';
        newForm.style.display   = 'flex';
        changeBtn.innerText     = '← Use Saved';
    } else {
        // Switch back to saved card
        loadSavedAwsCredentials();
    }
}

// --- Multi-Email Tag Functions ---

function addAutoEmail() {
    const input = document.getElementById('auto-email-input');
    const email = input.value.trim();
    
    if (!email) return;
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return showToast('Please enter a valid email address', 'error', 'Invalid Email');
    }
    
    if (autoConfig.emails.includes(email)) {
        return showToast('This email is already added', 'warning', 'Duplicate');
    }
    
    autoConfig.emails.push(email);
    input.value = '';
    renderEmailTags();
}

function removeAutoEmail(index) {
    autoConfig.emails.splice(index, 1);
    renderEmailTags();
}

function renderEmailTags() {
    const container = document.getElementById('auto-email-tags');
    if (!container) return;
    
    if (autoConfig.emails.length === 0) {
        container.innerHTML = `
            <div id="auto-email-empty" style="color: var(--text-secondary); font-size: 0.8rem; font-style: italic; width: 100%; text-align: center; opacity: 0.7;">
                No emails added yet.
            </div>`;
        return;
    }
    
    container.innerHTML = autoConfig.emails.map((email, index) => `
        <div class="email-tag" style="display: flex; align-items: center; gap: 8px; background: rgba(16, 185, 129, 0.12); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.25); padding: 5px 12px; border-radius: 20px; font-size: 0.82rem; font-weight: 600; animation: fadeIn 0.3s ease;">
            <ion-icon name="mail-outline" style="font-size: 0.9rem;"></ion-icon>
            <span>${email}</span>
            <button onclick="removeAutoEmail(${index})" style="background: none; border: none; color: #10b981; cursor: pointer; display: flex; align-items: center; padding: 2px; border-radius: 50%; hover: background: rgba(16, 185, 129, 0.2);">
                <ion-icon name="close-circle" style="font-size: 1.1rem;"></ion-icon>
            </button>
        </div>
    `).join('');
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
        document.getElementById('duration-group').style.display = 'none';
    } else if (freq === 'weekly') {
        dayRow.style.display = 'flex';
        dowGroup.style.display = 'block';
        domGroup.style.display = 'none';
        document.getElementById('date-group').style.display = 'none';
        document.getElementById('duration-group').style.display = 'none';
    } else if (freq === 'monthly') {
        dayRow.style.display = 'flex';
        dowGroup.style.display = 'none';
        // domGroup removed
        document.getElementById('date-group').style.display = 'none';
        document.getElementById('duration-group').style.display = 'flex';
    } else if (freq === 'once') {
        dayRow.style.display = 'none';
        document.getElementById('date-group').style.display = 'block';
        document.getElementById('duration-group').style.display = 'none';
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
        id: document.getElementById('current-schedule-id').value || null,
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

        dayOfMonth: 1, // Defaulting to 1 after UI removal
        date: document.getElementById('auto-date').value,
        startDate: document.getElementById('auto-start-date').value,
        endDate: document.getElementById('auto-end-date').value,
        notifyEmail: document.getElementById('auto-notify').checked,
        email: autoConfig.emails.join(', '),
        active: document.getElementById('auto-active').checked,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        selectedKeyId: document.getElementById('auto-key-select').value || null
    };

    // Validation for email if notifications are enabled
    if (config.notifyEmail && !config.email) {
        return showToast('At least one notification email is required', 'error', 'Missing Email');
    }

    // Handle AWS credentials — two modes: use saved profile creds OR enter new ones
    const platform = config.platform;
    if (platform === 'AWS') {
        const savedCard = document.getElementById('aws-saved-card');
        const usingSaved = savedCard && savedCard.style.display !== 'none';

        if (usingSaved) {
            // Saved credentials in profile will be used by scheduler automatically
            // No need to send credentials in this request
            config.credentials = null;
        } else {
            // User entered new credentials — validate
            const awsKeyId = document.getElementById('auto-aws-key-id').value.trim();
            const awsSecret = document.getElementById('auto-aws-secret-key').value.trim();
            if (!awsKeyId || !awsSecret) return showToast('Access Key ID aur Secret Access Key dono chahiye', 'error', 'Missing Credentials');
            config.credentials = { awsAccessKeyId: awsKeyId, awsSecretAccessKey: awsSecret };

            // Save to DB only if "Save for future scans" is checked
            const saveToProfile = document.getElementById('aws-save-to-profile');
            if (saveToProfile && saveToProfile.checked) {
                const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
                const userId = user?.email || user?.username;
                fetch('/api/user/aws-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId, accessKey: awsKeyId, secretKey: awsSecret, region: 'us-east-1' })
                }).then(r => r.json()).then(d => {
                    if (d.success) showToast('AWS credentials saved for future scans', 'success', 'Saved');
                }).catch(() => {});
            }
        }
    }

    try {
        const response = await fetch('/api/user/schedule', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('current-schedule-id').value = data.schedule._id;
            showToast('Schedule saved successfully', 'success');
            calculateNextScan();
            loadAllSchedules();
            updateHistoryLog('Schedule updated', 'success');
            
            // Hide form and show empty state after success
            setTimeout(() => {
                document.getElementById('automation-form-container').style.display = 'none';
                document.getElementById('automation-empty-state').style.display = 'block';
                window.showScheduleSuccessModal();
            }, 1500);
        } else {
            showToast('Failed to save: ' + data.message, 'error');
        }
    } catch (e) {
        showToast('Error saving schedule', 'error');
        console.error(e);
    }
}

async function loadSchedule(idOrPlatform) {
   if (!idOrPlatform) return;
   const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
   if (!user) return showToast('Please login first', 'error', 'Session Expired');

   console.log('Loading schedule for:', idOrPlatform);

   const userId = user.email || user.username;
   
   // We'll load keys AFTER we know the actual platform from the schedule
   // unless it's a direct platform load (New Mode)
   if (idOrPlatform.length <= 20) {
       await loadAvailableKeys(idOrPlatform);
   }

   try {
       let url = `/api/user/schedule?userId=${encodeURIComponent(userId)}`;
       if (idOrPlatform.length > 20) {
           url += `&id=${idOrPlatform}`;
       } else {
           url += `&platform=${idOrPlatform}`;
       }

       const response = await fetch(url);
       if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
       const data = await response.json();
       
       if (data.success && data.schedule) {
           const s = data.schedule;
           document.getElementById('current-schedule-id').value = s._id;
            
           // Update header and button
           const editorTitle = document.querySelector('#automation-content .panel-header h3');
           if (editorTitle) editorTitle.innerText = `Edit: ${s.platform} Schedule`;
           
           const saveBtn = document.getElementById('save-schedule-btn');
           if (saveBtn) saveBtn.innerText = 'Update Schedule';
                      // Show form, hide empty state
            document.getElementById('automation-form-container').style.display = 'block';
            document.getElementById('automation-empty-state').style.display = 'none';

            // Scroll to form now that it's visible
            document.getElementById('automation-form').scrollIntoView({ behavior: 'smooth', block: 'center' });

            // Load keys for the correct platform
            await loadAvailableKeys(s.platform);
           
           // Set Platform UI
           const options = document.querySelectorAll('#automation-form .cloud-option');
           options.forEach(opt => {
               if (opt.innerText.trim().toUpperCase() === s.platform.toUpperCase()) {
                   selectAutoPlatform(s.platform, opt, false);
               }
           });

            document.getElementById('auto-frequency').value = s.frequency || 'once';
            document.getElementById('auto-notify').checked = s.notifyEmail !== false;
            
            // Populate Email Tags
            const emailStr = s.email || user.email || '';
            autoConfig.emails = emailStr.split(',').map(e => e.trim()).filter(e => e !== '');
            renderEmailTags();
            
            document.getElementById('auto-active').checked = s.active !== false;
           if (s.date) document.getElementById('auto-date').value = s.date;
           
           if (s.selectedKeyId) {
               const keySelect = document.getElementById('auto-key-select');
               if (keySelect) keySelect.value = s.selectedKeyId;
           }

           // Populate AWS credentials if this is an AWS schedule
           if (s.platform === 'AWS' && s.credentials) {
               const keyIdEl = document.getElementById('auto-aws-key-id');
               const secretEl = document.getElementById('auto-aws-secret-key');
               if (keyIdEl && s.credentials.awsAccessKeyId) keyIdEl.value = s.credentials.awsAccessKeyId;
               if (secretEl && s.credentials.awsSecretAccessKey) secretEl.value = s.credentials.awsSecretAccessKey;
           }

           if (s.startDate) document.getElementById('auto-start-date').value = s.startDate.split('T')[0];
           if (s.endDate) document.getElementById('auto-end-date').value = s.endDate.split('T')[0];
           window.calculateDuration();

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
               const minSelect = document.getElementById('auto-time-minute');
               if (minSelect.value !== m) {
                   const opt = document.createElement('option');
                   opt.value = m;
                   opt.innerText = m;
                   minSelect.appendChild(opt);
                   Array.from(minSelect.options)
                       .sort((a, b) => parseInt(a.value) - parseInt(b.value))
                       .forEach(option => minSelect.add(option));
                   minSelect.value = m;
               }
               document.getElementById('auto-time-ampm').value = ampm;
           }
           
           if (s.dayOfWeek !== undefined && s.dayOfWeek !== null) {
               let days;
               if (Array.isArray(s.dayOfWeek)) {
                   days = s.dayOfWeek;
               } else if (typeof s.dayOfWeek === 'string') {
                   days = s.dayOfWeek.split(',').map(Number);
               } else {
                   // It's a single Number
                   days = [Number(s.dayOfWeek)];
               }

               autoConfig.days = days;
               document.querySelectorAll('.day-selector .day-btn').forEach((btn, idx) => {
                   if (days.includes(idx)) btn.classList.add('active');
                   else btn.classList.remove('active');
               });
           }
           
           toggleDayInputs();
           calculateNextScan();
       } else {
           // No schedule found for this platform — this is normal (first time setup)
           // Silently switch to "new schedule" creation mode
           document.getElementById('current-schedule-id').value = '';

           const editorTitle = document.querySelector('#automation-content .panel-header h3');
           if (editorTitle) editorTitle.innerText = `New ${idOrPlatform} Schedule`;

           const saveBtn = document.getElementById('save-schedule-btn');
           if (saveBtn) saveBtn.innerText = 'Save Schedule';

           // Show form, hide empty state
           document.getElementById('automation-form-container').style.display = 'block';
           document.getElementById('automation-empty-state').style.display = 'none';

           showToast(`No existing schedule for ${idOrPlatform}. Configure a new one below.`, 'info', 'New Schedule');
       }
   } catch(e) {
       console.error('Error loading schedule:', e);
       showToast('Critical error loading schedule: ' + e.message, 'error', 'System Error');
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

async function deleteSchedule(platform) {
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (!user) return showToast('Please login first', 'error');

    const userId = user.email || user.username;

    if (!(await showConfirm('Delete Schedule', `Are you sure you want to delete the scheduled scan for ${platform.toUpperCase()}?`, true))) return;

    try {
        const response = await fetch(`/api/user/schedule?userId=${encodeURIComponent(userId)}&platform=${platform}`, {
            method: 'DELETE'
        });
        const data = await response.json();

        if (data.success) {
            showToast('Schedule deleted successfully', 'success');
            // Reset UI
            loadSchedule(platform); 
            updateHistoryLog('Schedule deleted', 'warning');
        } else {
            showToast('Failed to delete: ' + data.message, 'error');
        }
    } catch (e) {
        showToast('Error deleting schedule', 'error');
        console.error(e);
    }
}

window.calculateDuration = function() {
    const startStr = document.getElementById('auto-start-date').value;
    const endStr = document.getElementById('auto-end-date').value;
    const display = document.getElementById('auto-duration-display');
    
    if (!display) return;

    if (!startStr || !endStr) {
        display.innerText = "0 Months";
        display.style.color = "var(--text-secondary)";
        display.style.background = "rgba(255, 255, 255, 0.05)";
        return;
    }
    
    const start = new Date(startStr);
    const end = new Date(endStr);
    
    if (end < start) {
        display.innerText = "Invalid Range";
        display.style.color = "#ef4444";
        display.style.background = "rgba(239, 68, 68, 0.1)";
        return;
    }
    
    let months = (end.getFullYear() - start.getFullYear()) * 12;
    months -= start.getMonth();
    months += end.getMonth();
    
    const result = Math.max(0, months);
    display.innerText = `${result} ${result === 1 ? 'Month' : 'Months'}`;
    display.style.color = "var(--cc-primary)";
    display.style.background = "rgba(16, 185, 129, 0.1)";
};

function calculateNextScan() {
    const active = document.getElementById('auto-active').checked;
    const nextScanEl = document.getElementById('next-scan-time');
    const statusTextEl = document.querySelector('.nav-status .status-text');
    const statusDotEl = document.querySelector('.nav-status .status-dot');

    if (!active) {
        if (nextScanEl) nextScanEl.innerText = 'Disabled';
        if (statusTextEl) statusTextEl.innerText = 'OFFLINE';
        if (statusDotEl) statusDotEl.style.background = 'var(--cc-text-muted)';
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
            const selectedDom = 1; // Defaulting to 1 after UI removal
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
    if (statusDotEl) statusDotEl.style.background = 'var(--cc-primary)';
}

function updateHistoryLog(msg, type) {
    const list = document.getElementById('auto-history-list');
    const item = document.createElement('div');
    item.style.display = 'flex';
    item.style.justifyContent = 'space-between';
    item.style.color = type === 'success' ? 'var(--cc-success)' : 'var(--cc-text-muted)';
    item.innerHTML = `<span>${msg}</span><span>${new Date().toLocaleTimeString()}</span>`;
    
    if (list.children[0]?.innerText.includes('No recent')) list.innerHTML = '';
    list.prepend(item);
}

// Init
function populateMinutes() {
    const minSelect = document.getElementById('auto-time-minute');
    if (!minSelect) return;
    minSelect.innerHTML = '';
    for (let i = 0; i < 60; i += 5) {
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
    loadAllSchedules();
    toggleDayInputs();
    // Set default email if logged in
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (user && user.email) {
        const emailInput = document.getElementById('auto-email');
        if (emailInput && !emailInput.value) emailInput.value = user.email;
    }
}, 1000);

window.resetAutomationForm = function() {
    // Reset header and button
    const editorTitle = document.querySelector('#automation-content .panel-header h3');
    if (editorTitle) editorTitle.innerText = 'New Schedule Configuration';

    const saveBtn = document.getElementById('save-schedule-btn');
    if (saveBtn) saveBtn.innerText = 'Save Schedule';

    document.getElementById('current-schedule-id').value = '';
    
    // Show form, hide empty state
    document.getElementById('automation-form-container').style.display = 'block';
    document.getElementById('automation-empty-state').style.display = 'none';
    
    // Force reset platform UI to GCP
    const gcpOpt = Array.from(document.querySelectorAll('#automation-form .cloud-option'))
        .find(opt => opt.innerText.trim() === 'GCP');
    if (gcpOpt) selectAutoPlatform('GCP', gcpOpt, false); 
    
    // Reset inputs
    document.getElementById('auto-frequency').value = 'once';
    document.getElementById('auto-date').value = '';
    document.getElementById('auto-notify').checked = true;
    document.getElementById('auto-active').checked = true;
    document.getElementById('delete-schedule-btn').style.display = 'none';
    
    // Reset Time
    document.getElementById('auto-time-hour').value = '09';
    const minSelect = document.getElementById('auto-time-minute');
    if (minSelect && minSelect.options.length > 0) minSelect.selectedIndex = 0;
    document.getElementById('auto-time-ampm').value = 'AM';

    // Reset Days
    autoConfig.days = [1];
    document.querySelectorAll('.day-selector .day-btn').forEach((btn, idx) => {
        if (idx === 1) btn.classList.add('active');
        else btn.classList.remove('active');
    });

    // Reset Keys
    const keySelect = document.getElementById('auto-key-select');
    if (keySelect) keySelect.selectedIndex = 0;

    // Reset Email (to logged in user)
    const user = JSON.parse(localStorage.getItem('gcp_audit_user') || '{}');
    if (user.email) document.getElementById('auto-email').value = user.email;
    else document.getElementById('auto-email').value = '';

    // Reset Duration
    document.getElementById('auto-start-date').value = '';
    document.getElementById('auto-end-date').value = '';
    window.calculateDuration();
    
    toggleDayInputs();
    calculateNextScan();
    
    // Smooth scroll to form
    const container = document.getElementById('automation-form-container');
    container.parentElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
    showToast('Ready for new automation', 'info', 'Notification');
};

async function loadAllSchedules() {
    const user = JSON.parse(localStorage.getItem('gcp_audit_user'));
    if (!user) return;

    const list = document.getElementById('active-schedules-list');
    const countEl = document.getElementById('active-schedules-count');
    if (!list) return;

    try {
        const userId = user.email || user.username;
        const response = await fetch(`/api/user/schedules?userId=${encodeURIComponent(userId)}`);
        const data = await response.json();

        if (data.success && data.schedules && data.schedules.length > 0) {
            countEl.innerText = data.schedules.length;
            list.innerHTML = '';
            data.schedules.forEach(s => {
                const item = document.createElement('div');
                item.className = 'glass';
                item.style.padding = '12px';
                item.style.borderRadius = '12px';
                item.style.border = '1px solid var(--border-color)';
                item.style.background = s.active ? 'rgba(26, 115, 232, 0.05)' : 'rgba(0, 0, 0, 0.05)';
                
                const timeStr = s.time || 'N/A';
                const freqStr = s.frequency ? s.frequency.charAt(0).toUpperCase() + s.frequency.slice(1) : 'Once';
                const lastScanStr = s.lastScan ? new Date(s.lastScan).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Never';
                
                item.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 10px;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                                <span class="badge ${s.platform === 'AWS' ? 'badge-warning' : 'badge-primary'}" style="font-size: 0.65rem;">${s.platform}</span>
                                <strong style="font-size: 0.85rem;">${freqStr} Audit</strong>
                            </div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary); display: flex; flex-direction: column; gap: 2px;">
                                <div style="display: flex; align-items: center; gap: 4px;">
                                    <ion-icon name="time-outline"></ion-icon> ${timeStr}
                                    ${s.date ? ` • <ion-icon name="calendar-outline"></ion-icon> ${s.date}` : ''}
                                </div>
                                <div style="font-size: 0.7rem; opacity: 0.8;">
                                    Last run: ${lastScanStr}
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 5px;">
                            <button onclick="console.log('Edit clicked for ID:', '${s._id}'); editScheduleFromList('${s._id}')" style="background: rgba(59, 130, 246, 0.1); color: var(--cc-primary); border: none; padding: 6px; border-radius: 6px; cursor: pointer; display: flex; transition: all 0.2s; position: relative; z-index: 10;" title="Edit">
                                <ion-icon name="create-outline"></ion-icon>
                            </button>
                            <button onclick="deleteScheduleFromList('${s._id}')" style="background: rgba(239, 68, 68, 0.1); color: #ef4444; border: none; padding: 6px; border-radius: 6px; cursor: pointer; display: flex; transition: all 0.2s;" title="Delete">
                                <ion-icon name="trash-outline"></ion-icon>
                            </button>
                        </div>
                    </div>
                `;
                list.appendChild(item);
            });
        } else {
            countEl.innerText = '0';
            list.innerHTML = `
                <div style="text-align: center; padding: 20px; color: var(--text-secondary); background: rgba(255, 255, 255, 0.03); border-radius: 12px; border: 1px dashed var(--border-color);">
                    <ion-icon name="calendar-outline" style="font-size: 1.5rem; opacity: 0.5;"></ion-icon>
                    <div style="font-size: 0.8rem; margin-top: 5px;">No active schedules</div>
                </div>
            `;
        }
    } catch (e) {
        console.error('Error loading all schedules:', e);
    }
}

window.editScheduleFromList = function(id) {
    loadSchedule(id);
};

window.deleteScheduleFromList = async function deleteScheduleFromList(id) {
    if (!(await showConfirm('Remove Scan', `Are you sure you want to delete this scheduled scan from your dashboard?`, true))) return;

    try {
        const response = await fetch(`/api/user/schedule?id=${id}`, {
            method: 'DELETE'
        });
        const data = await response.json();
        if (data.success) {
            showToast('Schedule deleted', 'success');
            loadAllSchedules();
            if (document.getElementById('current-schedule-id').value === id) {
                resetAutomationForm();
            }
        } else {
            showToast('Delete failed: ' + data.message, 'error');
        }
    } catch (e) {
        console.error('Error deleting schedule:', e);
    }
};

window.showScheduleSuccessModal = function() {
    document.getElementById('schedule-success-modal').style.display = 'flex';
};

window.closeScheduleSuccessModal = function() {
    document.getElementById('schedule-success-modal').style.display = 'none';
};

