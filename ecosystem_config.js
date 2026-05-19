module.exports = {
  apps: [{
    name: 'evrotarget-orgchart',
    script: 'server.js',
    cwd: '/home/bgrabanica/services/orgchart.js/orgchart-ket-drop3',
    instances: 1,
    exec_mode: 'fork',
    watch: false,
    max_memory_restart: '256M',
    error_file: 'logs/err.log',
    out_file: 'logs/out.log',
    merge_logs: true,
    time: true,

    env: {
      NODE_ENV: 'production',
      PORT: 3000,
      SESSION_SECRET: 'hRebEwVpjxAGlZK6cCoeiPLh9EFGTuxUynACcnbNz96nB918+tiwPPzB32KMkDX2',
      APP_BASE_URL: 'http://localhost:3000',
      SMTP_HOST: 'smtp.office365.com',
      SMTP_PORT: '587',
      SMTP_USER: 'besart.grabanica@evrotarget.com',
      SMTP_PASS: 'nJN4ygvE',
      MAIL_FROM: 'KiKxxl-evroTarget OrgChart <besart.grabanica@evrotarget.com>',
    }
  }]
};
