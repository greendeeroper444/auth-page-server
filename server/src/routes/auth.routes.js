const express = require('express');
const router = express.Router();

const {
    register,
    login,
    refreshToken,
    logout,
    logoutAll,
    verifyEmailAddress,
    resendEmailVerification,
    requestPasswordReset,
    resetPassword
} = require('../controllers/auth.controller');
const { authenticate } = require('../middlewares/auth.middleware');
const { 
    loginRateLimit, 
    passwordResetRateLimit, 
    emailVerificationRateLimit,
    speedLimiter,
    securityHeaders
} = require('../helpers/security.helper');

//apply security headers to all routes
router.use(securityHeaders);

//public routes (no authentication required)
router.post('/register', speedLimiter, register);
router.post('/login', loginRateLimit, login);
router.post('/refresh-token', refreshToken);
router.get('/verify-email', verifyEmailAddress);
router.post('/resend-verification', emailVerificationRateLimit, resendEmailVerification);
router.post('/forgot-password', passwordResetRateLimit, requestPasswordReset);
router.post('/reset-password', passwordResetRateLimit, resetPassword);

//protected routes (authentication required)
router.post('/logout', authenticate, logout);
router.post('/logout-all', authenticate, logoutAll);

module.exports = router;