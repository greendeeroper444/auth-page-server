const express = require('express');
const router = express.Router();

const AuthController = require('../controllers/auth.controller');
const { authenticate } = require('../middlewares/auth.middleware');
const { loginRateLimit, passwordResetRateLimit, emailVerificationRateLimit, speedLimiter, securityHeaders } = require('../helpers/security.helper');

//apply security headers to all routes
router.use(securityHeaders);

//public routes (no authentication required)
router.post(
    '/register', 
    speedLimiter, 
    AuthController.register.bind(AuthController)
);

router.post(
    '/login', 
    loginRateLimit, 
    AuthController.login.bind(AuthController)
);

router.post(
    '/refresh-token', 
    AuthController.refreshToken.bind(AuthController)
);

router.get(
    '/verify-email', 
    AuthController.verifyEmailAddress.bind(AuthController)
);

router.post(
    '/resend-verification', 
    emailVerificationRateLimit, 
    AuthController.resendEmailVerification.bind(AuthController)
);

router.post(
    '/forgot-password', 
    passwordResetRateLimit, 
    AuthController.requestPasswordReset.bind(AuthController)
);

router.post(
    '/reset-password', 
    passwordResetRateLimit, 
    AuthController.resetPassword.bind(AuthController)
);


//protected routes (authentication required)
router.post(
    '/logout', 
    authenticate, 
    AuthController.logout.bind(AuthController)
);

router.post(
    '/logout-all', 
    authenticate, 
    AuthController.logoutAll.bind(AuthController)
);

module.exports = router;