// mailer.js — small wrapper around nodemailer for invite + password-reset emails.
//
// Configure via environment variables in ecosystem.config.js:
//   SMTP_HOST   e.g. smtp.office365.com  /  smtp.gmail.com
//   SMTP_PORT   e.g. 587
//   SMTP_USER   e.g. orgchart@kikxxl-evrotarget.com
//   SMTP_PASS   the SMTP / app password
//   MAIL_FROM   e.g. "KiKxxl-evroTarget OrgChart <orgchart@kikxxl-evrotarget.com>"
//   APP_BASE_URL e.g. https://orgchart.kikxxl-evrotarget.com  (used in links)
//
// If SMTP_HOST is not set, mailer enters DRY-RUN mode: emails are logged to the
// console instead of being sent. Useful for local development.

let nodemailer;
try { nodemailer = require('nodemailer'); }
catch (e) { console.warn('  ⚠️   nodemailer not installed. Run: npm install nodemailer'); }

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.office365.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER || 'besart.grabanica@evrotarget.com';
const SMTP_PASS = process.env.SMTP_PASS || 'nJN4ygvE';
const MAIL_FROM = process.env.MAIL_FROM || `KiKxxl-evroTarget OrgChart <${SMTP_USER}>`;
const APP_BASE_URL = (process.env.APP_BASE_URL || 'http://localhost:3000').replace(/\/$/, '');

const dryRun = !SMTP_HOST || !nodemailer;
let transporter = null;

if (!dryRun) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
  });
  console.log(`  ✅  Mailer: SMTP ${SMTP_HOST}:${SMTP_PORT} as ${SMTP_USER || '(no auth)'}`);
} else {
  console.log('  ⚠️   Mailer: DRY-RUN (no SMTP_HOST set — emails will be logged, not sent)');
}

function htmlEscape(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

function wrapHtml(title, bodyHtml) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>${htmlEscape(title)}</title></head>
<body style="margin:0;padding:0;background:#f0f4ff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr><td align="center" style="padding:32px 16px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;background:#ffffff;border-radius:14px;box-shadow:0 4px 20px rgba(29,78,216,.08);overflow:hidden;">
        <tr><td style="padding:24px 28px 0;">
          <div style="display:inline-block;background:#1d4ed8;color:#ffffff;font-size:11px;font-weight:700;letter-spacing:1px;padding:5px 10px;border-radius:5px;text-transform:uppercase;">KiKxxl-evroTarget</div>
        </td></tr>
        <tr><td style="padding:18px 28px 28px;color:#111827;font-size:15px;line-height:1.6;">
          ${bodyHtml}
        </td></tr>
        <tr><td style="padding:16px 28px 24px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:12px;">
          You received this because someone with admin access at KiKxxl-evroTarget initiated this action. If this wasn't expected, you can safely ignore this email.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

async function sendMail({ to, subject, html, text }) {
  const opts = {
    from: MAIL_FROM,
    to, subject, html,
    text: text || html.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim(),
  };
  if (dryRun) {
    console.log('\n  📧  [DRY-RUN] would send mail:');
    console.log('       To:      ' + to);
    console.log('       Subject: ' + subject);
    console.log('       (set SMTP_HOST + creds in ecosystem.config.js to send for real)\n');
    return { dryRun: true };
  }
  return await transporter.sendMail(opts);
}

async function sendInviteEmail({ to, role, token, invitedByName }) {
  const link = `${APP_BASE_URL}/accept-invite.html?token=${encodeURIComponent(token)}`;
  const html = wrapHtml("You're invited to KiKxxl-evroTarget OrgChart", `
    <h2 style="margin:0 0 12px;font-size:18px;color:#111827;">You're invited</h2>
    <p>${htmlEscape(invitedByName || 'An admin')} has invited you to join the <strong>KiKxxl-evroTarget Organization Chart</strong> as a <strong>${htmlEscape(role)}</strong>.</p>
    <p>Click the button below to choose a username and password and activate your account.</p>
    <p style="margin:22px 0 12px;"><a href="${link}" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:600;padding:11px 22px;border-radius:8px;">Accept invite</a></p>
    <p style="font-size:13px;color:#6b7280;">Or paste this link into your browser:<br/><span style="word-break:break-all;">${link}</span></p>
    <p style="font-size:13px;color:#6b7280;margin-top:18px;">This invite expires in <strong>30 days</strong>.</p>
  `);
  return sendMail({ to, subject: 'You are invited to KiKxxl-evroTarget OrgChart', html });
}

async function sendPasswordResetEmail({ to, token, username }) {
  const link = `${APP_BASE_URL}/reset-password.html?token=${encodeURIComponent(token)}`;
  const html = wrapHtml('Reset your KiKxxl-evroTarget password', `
    <h2 style="margin:0 0 12px;font-size:18px;color:#111827;">Reset your password</h2>
    <p>Someone (hopefully you) requested a password reset for the account <strong>${htmlEscape(username)}</strong> on the KiKxxl-evroTarget Organization Chart.</p>
    <p>Click the button below within the next hour to choose a new password.</p>
    <p style="margin:22px 0 12px;"><a href="${link}" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:600;padding:11px 22px;border-radius:8px;">Reset password</a></p>
    <p style="font-size:13px;color:#6b7280;">Or paste this link into your browser:<br/><span style="word-break:break-all;">${link}</span></p>
    <p style="font-size:13px;color:#6b7280;margin-top:18px;">If you didn't request a reset, ignore this email — your password won't change.</p>
    <p style="font-size:13px;color:#6b7280;">This link expires in <strong>1 hour</strong>.</p>
  `);
  return sendMail({ to, subject: 'Reset your KiKxxl-evroTarget password', html });
}

module.exports = {
  sendInviteEmail,
  sendPasswordResetEmail,
  dryRun,
};
