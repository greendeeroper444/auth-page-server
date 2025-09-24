const express = require('express');
const router = express.Router();

const {
    getProfile,
    updateProfile,
    changePassword,
    getStats,
    getLoginHistory,
    deleteAccount,
    getAllUsers,
    getUserById,
    updateUserRole,
    updateAccountStatus
} = require('../controllers/user.controller');
const {
    authenticate,
    requireRole,
    requireAnyRole,
    requirePermission,
    requireEmailVerification,
    requireOwnershipOrAdmin,
    logUserActivity
} = require('../middlewares/auth.middleware');

const { securityHeaders } = require('../helpers/security.helper');

//apply security headers and authentication to all routes
router.use(securityHeaders);
router.use(authenticate);

//user profile routes
router.get('/profile', getProfile);
router.put('/profile', updateProfile);
router.get('/stats', getStats);
router.get('/login-history', getLoginHistory);

//password management
router.put('/change-password', requireEmailVerification, changePassword);

//account management
router.delete('/account', requireEmailVerification, logUserActivity, deleteAccount);

//admin routes - user management
router.get('/', requireAnyRole(['admin', 'superadmin']), getAllUsers);
router.get('/:userId', requirePermission('manage_users'), getUserById);
router.put('/:userId/role', requireAnyRole(['admin', 'superadmin']), logUserActivity, updateUserRole);
router.put('/:userId/status', requirePermission('manage_users'), logUserActivity, updateAccountStatus);

module.exports = router;