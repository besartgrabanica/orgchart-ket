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

      // Generate with:
      // node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
      SESSION_SECRET: 'CHANGE-THIS-TO-A-LONG-RANDOM-STRING',

      // URL users hit in their browser (used in invite + reset email links)
      APP_BASE_URL: 'http://localhost:3000',

      // SMTP — leave SMTP_HOST empty for dry-run mode (emails print to logs)
      SMTP_HOST: '',
      SMTP_PORT: '587',
      SMTP_USER: 'orgchart@kikxxl-evrotarget.com',
      SMTP_PASS: 'YOUR-SMTP-APP-PASSWORD',
      MAIL_FROM: 'KiKxxl-evroTarget OrgChart <orgchart@kikxxl-evrotarget.com>',
    }
  }]
};
