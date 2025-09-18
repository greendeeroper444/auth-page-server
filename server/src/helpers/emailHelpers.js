const nodemailer = require('nodemailer');
const config = require('../config/environment');

/**
 * create email transporter
 * @returns {Object} nodemailer transporter
 */
const createTransporter = () => {
    //configuration for different email providers
    const emailConfig = {
        gmail: {
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_APP_PASSWORD //app password for Gmail
            }
        },
        smtp: {
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            }
        },
        development: {
            //for development, use Ethereal Email (temporary accounts)
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false,
            auth: {
                user: 'ethereal.user@ethereal.email',
                pass: 'ethereal.pass'
            }
        }
    };
    
    const provider = process.env.EMAIL_PROVIDER || 'smtp';
    const transportConfig = emailConfig[provider] || emailConfig.smtp;
    
    //fixed: Use nodemailer.createTransport instead of createTransporter
    return nodemailer.createTransport(transportConfig);
};

/**
 * generate email verification template
 * @param {String} name - user's name
 * @param {String} verificationUrl - verification URL
 * @returns {Object} email template
 */
const getEmailVerificationTemplate = (name, verificationUrl) => {
    const subject = 'Verify Your Email Address';
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #007bff; color: white; padding: 20px; text-align: center; }
            .content { padding: 30px; background: #f8f9fa; }
            .button { 
                display: inline-block; 
                padding: 12px 30px; 
                background: #28a745; 
                color: white; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }
            .footer { padding: 20px; text-align: center; color: #6c757d; font-size: 14px; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Email Verification Required</h1>
            </div>
            <div class="content">
                <h2>Hello ${name}!</h2>
                <p>Thank you for creating an account with us. To complete your registration, please verify your email address by clicking the button below:</p>
                
                <div style="text-align: center;">
                    <a href="${verificationUrl}" class="button">Verify Email Address</a>
                </div>
                
                <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #007bff;">${verificationUrl}</p>
                
                <div class="warning">
                    <strong>Security Notice:</strong> This verification link will expire in 24 hours. If you didn't create this account, you can safely ignore this email.
                </div>
            </div>
            <div class="footer">
                <p>This email was sent from an automated system. Please do not reply to this email.</p>
                <p>&copy; ${new Date().getFullYear()} Auth Secure. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;
    
    const text = `
    Hello ${name}!
    
    Thank you for creating an account with us. To complete your registration, please verify your email address by visiting this link:
    
    ${verificationUrl}
    
    This verification link will expire in 24 hours.
    
    If you didn't create this account, you can safely ignore this email.
    
    This is an automated email. Please do not reply.
    `;
    
    return { subject, html, text };
};

/**
 * generate password reset template
 * @param {String} name - user's name
 * @param {String} resetUrl - password reset URL
 * @returns {Object} email template
 */
const getPasswordResetTemplate = (name, resetUrl) => {
    const subject = 'Password Reset Request';
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
            .content { padding: 30px; background: #f8f9fa; }
            .button { 
                display: inline-block; 
                padding: 12px 30px; 
                background: #dc3545; 
                color: white; 
                text-decoration: none; 
                border-radius: 5px;
                margin: 20px 0;
            }
            .footer { padding: 20px; text-align: center; color: #6c757d; font-size: 14px; }
            .warning { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Reset Request</h1>
            </div>
            <div class="content">
                <h2>Hello ${name}!</h2>
                <p>We received a request to reset your password. If you made this request, click the button below to reset your password:</p>
                
                <div style="text-align: center;">
                    <a href="${resetUrl}" class="button">Reset Password</a>
                </div>
                
                <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #dc3545;">${resetUrl}</p>
                
                <div class="warning">
                    <strong>Security Notice:</strong> This reset link will expire in 10 minutes. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
                </div>
                
                <p>For your security, this request came from the following location:</p>
                <p><small>If this wasn't you, please contact our support team immediately.</small></p>
            </div>
            <div class="footer">
                <p>This email was sent from an automated system. Please do not reply to this email.</p>
                <p>&copy; ${new Date().getFullYear()} Auth Secure. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;
    
    const text = `
    Hello ${name}!
    
    We received a request to reset your password. If you made this request, visit this link to reset your password:
    
    ${resetUrl}
    
    This reset link will expire in 10 minutes.
    
    If you didn't request a password reset, please ignore this email and your password will remain unchanged.
    
    This is an automated email. Please do not reply.
    `;
    
    return { subject, html, text };
};

/**
 * generate welcome email template
 * @param {String} name - user's name
 * @returns {Object} email template
 */
const getWelcomeTemplate = (name) => {
    const subject = 'Welcome to Auth Secure!';
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #28a745; color: white; padding: 20px; text-align: center; }
            .content { padding: 30px; background: #f8f9fa; }
            .feature { margin: 20px 0; padding: 15px; background: white; border-radius: 5px; }
            .footer { padding: 20px; text-align: center; color: #6c757d; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Welcome to Auth Secure!</h1>
            </div>
            <div class="content">
                <h2>Hello ${name}!</h2>
                <p>Your email has been successfully verified and your account is now active. Welcome to Auth Secure!</p>
                
                <div class="feature">
                    <h3>🔐 Your account features:</h3>
                    <ul>
                        <li>Secure authentication with JWT tokens</li>
                        <li>Two-factor authentication available</li>
                        <li>Login history tracking</li>
                        <li>Password reset functionality</li>
                    </ul>
                </div>
                
                <div class="feature">
                    <h3>🛡️ Security Tips:</h3>
                    <ul>
                        <li>Use a strong, unique password</li>
                        <li>Enable two-factor authentication</li>
                        <li>Keep your email address secure</li>
                        <li>Log out from shared devices</li>
                    </ul>
                </div>
                
                <p>If you have any questions or need help, don't hesitate to contact our support team.</p>
            </div>
            <div class="footer">
                <p>Thank you for choosing Auth Secure!</p>
                <p>&copy; ${new Date().getFullYear()} Auth Secure. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;
    
    const text = `
    Hello ${name}!
    
    Your email has been successfully verified and your account is now active. Welcome to Auth Secure!
    
    Your account features:
    - Secure authentication with JWT tokens
    - Two-factor authentication available
    - Login history tracking
    - Password reset functionality
    
    Security Tips:
    - Use a strong, unique password
    - Enable two-factor authentication
    - Keep your email address secure
    - Log out from shared devices
    
    If you have any questions or need help, don't hesitate to contact our support team.
    
    Thank you for choosing Auth Secure!
    `;
    
    return { subject, html, text };
};

/**
 * send email verification
 * @param {String} email - recipient email
 * @param {String} name - recipient name
 * @param {String} verificationToken - verification token
 * @returns {Promise<Boolean>} send success
 */
const sendEmailVerification = async (email, name, verificationToken) => {
    try {
        const transporter = createTransporter();
        const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}`;
        const template = getEmailVerificationTemplate(name, verificationUrl);
        
        const mailOptions = {
            from: `"Auth Secure" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to: email,
            subject: template.subject,
            html: template.html,
            text: template.text
        };
        
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Failed to send verification email:', error);
        return false;
    }
};

/**
 * send password reset email
 * @param {String} email - recipient email
 * @param {String} name - recipient name
 * @param {String} resetToken - reset token
 * @returns {Promise<Boolean>} send success
 */
const sendPasswordReset = async (email, name, resetToken) => {
    try {
        const transporter = createTransporter();
        const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
        const template = getPasswordResetTemplate(name, resetUrl);
        
        const mailOptions = {
            from: `"Auth Secure" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to: email,
            subject: template.subject,
            html: template.html,
            text: template.text
        };
        
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Failed to send password reset email:', error);
        return false;
    }
};

/**
 * send welcome email
 * @param {String} email - recipient email
 * @param {String} name - recipient name
 * @returns {Promise<Boolean>} send success
 */
const sendWelcomeEmail = async (email, name) => {
    try {
        const transporter = createTransporter();
        const template = getWelcomeTemplate(name);
        
        const mailOptions = {
            from: `"Auth Secure" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to: email,
            subject: template.subject,
            html: template.html,
            text: template.text
        };
        
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Failed to send welcome email:', error);
        return false;
    }
};

/**
 * test email configuration
 * @returns {Promise<Boolean>} test success
 */
const testEmailConfig = async () => {
    try {
        const transporter = createTransporter();
        await transporter.verify();
        console.log('Email configuration is valid');
        return true;
    } catch (error) {
        console.error('Email configuration error:', error);
        return false;
    }
};

module.exports = {
    sendEmailVerification,
    sendPasswordReset,
    sendWelcomeEmail,
    testEmailConfig,
    getEmailVerificationTemplate,
    getPasswordResetTemplate,
    getWelcomeTemplate
};