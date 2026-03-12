# AuditScope - Unified Cloud Security Auditor

AuditScope is a premium cloud security auditing platform designed to scan, analyze, and monitor security risks across GCP, AWS, and Azure environments.

## 🚀 Getting Started on Server

Follow these steps to deploy and run the application on your server.

### 1. Prerequisites

Ensure you have the following installed:
- **Node.js** (v16 or higher)
- **MongoDB** (Running locally or a connection URI)
- **NPM** (Node Package Manager)

### 2. Installation

Clone the repository and install dependencies:

```bash
cd gcp-security-audit
npm install
```

### 3. Database Configuration

The application connects to MongoDB at `mongodb://127.0.0.1:27017/gcp-audit`. 
Make sure your MongoDB service is running:

```bash
# On Linux (Ubuntu/Debian)
sudo systemctl start mongod
```

### 4. Running the Application

#### Option A: Development Mode (with auto-restart)
```bash
npm run dev
```

#### Option B: Production Mode (using PM2)
If you want the server to run in the background and restart automatically:

```bash
# Install PM2 globally if not already installed
sudo npm install -g pm2

# Start the application
pm2 start ecosystem.config.js

# To see logs
pm2 logs
```

### 5. Accessing the Dashboard

Once the server is running, you can access the portal at:
- **URL:** `http://localhost:8080` (or your server's IP address)
- **Default Port:** 8080

### 6. Troubleshooting

- **Logs Persistence:** All scan logs are persisted in local storage. If logs aren't appearing, ensure you are logged in.
- **Invitations:** Portal links in invitation emails point to `http://localhost:8080` by default. Update `email_service.js` if deploying on a domain.

---
Developed by Cloud Ambassadors Security Team.
