const express = require('express');
const router = express.Router();

const UserController = require('../controllers/user.controller');
const { authenticate, requireAnyRole, requirePermission, requireEmailVerification, logUserActivity } = require('../middlewares/auth.middleware');

const { securityHeaders } = require('../helpers/security.helper');

//security headers and authentication to all routes
router.use(securityHeaders);
router.use(authenticate);

//user profile routes
router.get(
    '/profile', 
    UserController.getProfile.bind(UserController)
);

router.put(
    '/profile', 
    UserController.updateProfile.bind(UserController)
);
router.get(
    '/stats', 
    UserController.getStats.bind(UserController)
);

router.get(
    '/login-history', 
    UserController.getLoginHistory.bind(UserController)
);

//password management
router.put(
    '/change-password', 
    requireEmailVerification, 
    UserController.changePassword.bind(UserController)
);


//account management
router.delete(
    '/account', 
    requireEmailVerification, 
    logUserActivity, 
    UserController.deleteAccount.bind(UserController)
);


//admin routes - user management
router.get(
    '/', 
    requireAnyRole(['admin', 'superadmin']), 
    UserController.getAllUsers.bind(UserController)
);

router.get(
    '/:userId', 
    requirePermission('manage_users'), 
    UserController.getUserById.bind(UserController)
);

router.put(
    '/:userId/role', 
    requireAnyRole(['admin', 'superadmin']), 
    logUserActivity, 
    UserController.updateUserRole.bind(UserController)
);

router.put(
    '/:userId/status', 
    requirePermission('manage_users'), 
    logUserActivity, 
    UserController.updateAccountStatus.bind(UserController)
);

module.exports = router;