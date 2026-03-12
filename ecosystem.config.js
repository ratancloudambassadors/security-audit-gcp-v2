module.exports = {
  apps: [
    {
      name: 'gcp-security-audit',
      script: 'server.js',
      cwd: '/home/hp/ratan/gcp-security-audit',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        PORT: 8080
      },
      out_file: '/home/hp/ratan/gcp-security-audit/logs/out.log',
      error_file: '/home/hp/ratan/gcp-security-audit/logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      restart_delay: 5000,
      max_restarts: 10,
      min_uptime: '10s'
    }
  ]
};
