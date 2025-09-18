const User = require('../models/user.model');

/**
 * find user by email or username
 * @param {String} identifier - email or username
 * @returns {Promise<Object|null>} user document or null
 */
const findUserByEmailOrUsername = async (identifier) => {
    return await User.findOne({
        $or: [
            { email: identifier.toLowerCase() },
            { username: identifier }
        ]
    });
};

/**
 * find user for login (includes password field)
 * @param {String} identifier - email or username
 * @returns {Promise<Object|null>} user document with password or null
 */
const findUserForLogin = async (identifier) => {
    return await User.findOne({
        $or: [
            { email: identifier.toLowerCase() },
            { username: identifier }
        ]
    }).select('+password +loginAttempts +lockUntil');
};

/**
 * handle failed login attempts
 * @param {Object} user - user document
 * @returns {Promise<Object>} update result
 */
const handleFailedLoginAttempt = async (user) => {
    //if previous lock expired, restart at 1
    if (user.lockUntil && user.lockUntil < Date.now()) {
        return await User.updateOne(
            { _id: user._id },
            {
                $unset: { lockUntil: 1 },
                $set: { loginAttempts: 1 }
            }
        );
    }
    
    const updates = { $inc: { loginAttempts: 1 } };
    
    //lock account after 5 failed attempts
    if (user.loginAttempts + 1 >= 5 && !user.isLocked) {
        updates.$set = { 
            lockUntil: Date.now() + 2 * 60 * 60 * 1000 // 2 hours
        };
    }
    
    return await User.updateOne({ _id: user._id }, updates);
};

/**
 * reset login attempts after successful login
 * @param {String} userId - user ID
 * @returns {Promise<Object>} update result
 */
const resetLoginAttempts = async (userId) => {
    return await User.updateOne(
        { _id: userId },
        {
            $unset: { 
                loginAttempts: 1, 
                lockUntil: 1 
            }
        }
    );
};

/**
 * add login history entry
 * @param {String} userId - user ID
 * @param {String} ip - IP address
 * @param {String} userAgent - user agent string
 * @param {Boolean} success - login success status
 * @returns {Promise<Object>} update result
 */
const addLoginHistory = async (userId, ip, userAgent, success = true) => {
    const loginEntry = {
        ip,
        userAgent,
        success,
        timestamp: new Date()
    };
    
    const updates = {
        $push: {
            loginHistory: {
                $each: [loginEntry],
                $slice: -10 //keep only last 10 entries
            }
        }
    };
    
    if (success) {
        updates.$set = { lastLogin: new Date() };
    }
    
    return await User.updateOne({ _id: userId }, updates);
};

/**
 * add refresh token to user
 * @param {String} userId - user ID
 * @param {String} token - refresh token
 * @returns {Promise<Object>} update result
 */
const addRefreshToken = async (userId, token) => {
    return await User.updateOne(
        { _id: userId },
        {
            $push: {
                refreshTokens: {
                    $each: [{ token }],
                    $slice: -5 //keep only last 5 tokens
                }
            }
        }
    );
};

/**
 * remove refresh token from user
 * @param {String} userId - user ID
 * @param {String} token - refresh token to remove
 * @returns {Promise<Object>} update result
 */
const removeRefreshToken = async (userId, token) => {
    return await User.updateOne(
        { _id: userId },
        {
            $pull: {
                refreshTokens: { token }
            }
        }
    );
};

/**
 * remove all refresh tokens from user (logout from all devices)
 * @param {String} userId - user ID
 * @returns {Promise<Object>} update result
 */
const removeAllRefreshTokens = async (userId) => {
    return await User.updateOne(
        { _id: userId },
        {
            $set: { refreshTokens: [] }
        }
    );
};

/**
 * check if user has specific permission
 * @param {Object} user - user document
 * @param {String} permission - permission to check
 * @returns {Boolean} has permission
 */
const hasPermission = (user, permission) => {
    //super admin has all permissions
    if (user.role === 'superadmin') return true;
    
    //admin has most permissions
    if (user.role === 'admin') {
        const adminPermissions = ['read', 'write', 'delete', 'manage_users'];
        return adminPermissions.includes(permission);
    }
    
    //check specific permissions array
    return user.permissions && user.permissions.includes(permission);
};

/**
 * check if user has specific role
 * @param {Object} user - user document
 * @param {String} role - role to check
 * @returns {Boolean} has role
 */
const hasRole = (user, role) => {
    return user.role === role;
};

/**
 * check if user has any of the specified roles
 * @param {Object} user - user document
 * @param {Array} roles - array of roles to check
 * @returns {Boolean} has any of the roles
 */
const hasAnyRole = (user, roles) => {
    return roles.includes(user.role);
};

/**
 * update user password reset token
 * @param {String} userId - user ID
 * @param {String} hashedToken - hashed reset token
 * @param {Date} expires - expiration date
 * @returns {Promise<Object>} update result
 */
const setPasswordResetToken = async (userId, hashedToken, expires) => {
    return await User.updateOne(
        { _id: userId },
        {
            passwordResetToken: hashedToken,
            passwordResetExpires: expires
        }
    );
};

/**
 * update user email verification token
 * @param {String} userId - user ID
 * @param {String} hashedToken - hashed verification token
 * @param {Date} expires - expiration date
 * @returns {Promise<Object>} update result
 */
const setEmailVerificationToken = async (userId, hashedToken, expires) => {
    return await User.updateOne(
        { _id: userId },
        {
            emailVerificationToken: hashedToken,
            emailVerificationExpires: expires
        }
    );
};

/**
 * verify email and update user status
 * @param {String} hashedToken - hashed verification token
 * @returns {Promise<Object|null>} user document or null
 */
const verifyEmail = async (hashedToken) => {
    const user = await User.findOneAndUpdate(
        {
            emailVerificationToken: hashedToken,
            emailVerificationExpires: { $gt: Date.now() }
        },
        {
            $set: {
                isEmailVerified: true,
                accountStatus: 'active'
            },
            $unset: {
                emailVerificationToken: 1,
                emailVerificationExpires: 1
            }
        },
        { new: true }
    );
    
    return user;
};

/**
 * get user statistics
 * @param {String} userId - user ID
 * @returns {Promise<Object>} user statistics
 */
const getUserStats = async (userId) => {
    const user = await User.findById(userId);
    if (!user) return null;
    
    return {
        totalLogins: user.loginHistory.filter(entry => entry.success).length,
        failedLogins: user.loginHistory.filter(entry => !entry.success).length,
        lastLogin: user.lastLogin,
        accountAge: Date.now() - user.createdAt.getTime(),
        isLocked: user.isLocked,
        activeTokens: user.refreshTokens.length
    };
};

module.exports = {
    findUserByEmailOrUsername,
    findUserForLogin,
    handleFailedLoginAttempt,
    resetLoginAttempts,
    addLoginHistory,
    addRefreshToken,
    removeRefreshToken,
    removeAllRefreshTokens,
    hasPermission,
    hasRole,
    hasAnyRole,
    setPasswordResetToken,
    setEmailVerificationToken,
    verifyEmail,
    getUserStats
};