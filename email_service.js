const nodemailer = require('nodemailer');

const createEmailTemplate = (results) => {
    const { platform, summary, accountId, projectId, timestamp } = results;
    const severity = summary.high > 0 ? 'High' : (summary.medium > 0 ? 'Medium' : 'Low');
    const color = severity === 'High' ? '#d93025' : (severity === 'Medium' ? '#f9ab00' : '#1e8e3e');

    return `
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f7f6;">
        <div style="max-width: 650px; margin: auto; border: 1px solid #e0e0e0; border-radius: 12px; overflow: hidden; background: white; box-shadow: 0 4px 15px rgba(0,0,0,0.05);">
            <div style="background: linear-gradient(135deg, #1a73e8 0%, #0d47a1 100%); color: white; padding: 30px 20px; text-align: center;">
                <h1 style="margin: 0; font-size: 24px; letter-spacing: 0.5px;">Cloud Security Report</h1>
                <p style="margin: 5px 0 0; opacity: 0.9;">Automated Security Posture Analysis</p>
            </div>
            
            <div style="padding: 30px;">
                <div style="text-align: center; margin-bottom: 25px;">
                    <span style="background: ${color}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 14px; text-transform: uppercase;">
                        Risk Level: ${severity}
                    </span>
                </div>
                
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 25px; font-size: 14px;">
                    <tr style="background-color: #f9fafb;">
                        <td style="padding: 12px; border-bottom: 1px solid #edf2f7; color: #718096;"><strong>Cloud Platform</strong></td>
                        <td style="padding: 12px; border-bottom: 1px solid #edf2f7; text-align: right; color: #2d3748;">${platform}</td>
                    </tr>
                    <tr>
                        <td style="padding: 12px; border-bottom: 1px solid #edf2f7; color: #718096;"><strong>Account / Project ID</strong></td>
                        <td style="padding: 12px; border-bottom: 1px solid #edf2f7; text-align: right; color: #2d3748;">${projectId || accountId || 'N/A'}</td>
                    </tr>
                    <tr style="background-color: #f9fafb;">
                        <td style="padding: 12px; border-bottom: 1px solid #edf2f7; color: #718096;"><strong>Scan Timestamp</strong></td>
                        <td style="padding: 12px; border-bottom: 1px solid #edf2f7; text-align: right; color: #2d3748;">${new Date(timestamp).toLocaleString()}</td>
                    </tr>
                </table>

                <div style="background: #ffffff; padding: 20px; border: 1px solid #e2e8f0; border-radius: 10px; margin-bottom: 30px;">
                    <h3 style="margin-top: 0; font-size: 16px; color: #2d3748; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 15px;">Vulnerability Summary</h3>
                    <div style="display: flex; justify-content: space-between; text-align: center;">
                        <div style="flex: 1; padding: 10px;">
                            <div style="font-size: 24px; font-weight: bold; color: #d93025;">${summary.high}</div>
                            <div style="font-size: 12px; color: #718096; text-transform: uppercase; margin-top: 4px;">Critical</div>
                        </div>
                        <div style="flex: 1; padding: 10px; border-left: 1px solid #edf2f7; border-right: 1px solid #edf2f7;">
                            <div style="font-size: 24px; font-weight: bold; color: #f9ab00;">${summary.medium}</div>
                            <div style="font-size: 12px; color: #718096; text-transform: uppercase; margin-top: 4px;">Warning</div>
                        </div>
                        <div style="flex: 1; padding: 10px;">
                            <div style="font-size: 24px; font-weight: bold; color: #1e8e3e;">${summary.low + (summary.secure || 0)}</div>
                            <div style="font-size: 12px; color: #718096; text-transform: uppercase; margin-top: 4px;">Safe / Low</div>
                        </div>
                    </div>
                </div>

                <div style="text-align: center; margin-top: 10px;">
                    <p style="font-size: 14px; color: #4a5568; margin-bottom: 20px;">Detailed findings and remediation steps are available in your dashboard.</p>
                    <a href="http://localhost:8080/dashboard" style="display: inline-block; background: #1a73e8; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 15px; box-shadow: 0 2px 5px rgba(26,115,232,0.3);">Access Live Dashboard</a>
                </div>
            </div>
            
            <div style="background: #f8fafc; padding: 20px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #edf2f7;">
                This is an automatically generated security report.<br>
                Please do not reply to this email.<br><br>
                &copy; 2026 AuditScope • Cloud Security Intelligence
            </div>
        </div>
    </body>
    </html>
    `;
};

async function sendSecurityReport(toEmail, results) {
    console.log(`[EMAIL_DEBUG] Attempting to send email to ${toEmail}`);
    console.log(`[EMAIL_DEBUG] Results Payload:`, JSON.stringify(results, null, 2));
    console.log(`[EMAIL_DEBUG] SMTP Config: User present? ${!!process.env.SMTP_USER}, Pass present? ${!!process.env.SMTP_PASS}`);

    // Configure transporter (using environment variables for security)
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: process.env.SMTP_PORT || 587,
        secure: false, // true for 465, false for other ports
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });

    try {
        const info = await transporter.sendMail({
            from: `"AuditScope Security" <${process.env.SMTP_USER}>`,
            to: toEmail,
            subject: `Cloud Security Report: ${results.platform} - ${results.summary.high} Critical Issues`,
            html: createEmailTemplate(results),
        });

        console.log(`[EMAIL] Report sent to ${toEmail}: ${info.messageId}`);
        return true;
    } catch (error) {
        console.error(`[EMAIL] Delivery failed to ${toEmail}:`, error.message);
        return false;
    }
}

module.exports = { sendSecurityReport };
