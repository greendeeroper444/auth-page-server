const User = require('../models/user.model');

const findUserByEmailOrUsername = async (identifier) => {
    return await User.findOne({
        $or: [
            { email: identifier.toLowerCase() },
            { username: identifier }
        ]
    });
};

const findUserForLogin = async (identifier) => {
    return await User.findOne({
        $or: [
            { email: identifier.toLowerCase() },
            { username: identifier }
        ]
    }).select('+password +loginAttempts +lockUntil');
};

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

const removeAllRefreshTokens = async (userId) => {
    return await User.updateOne(
        { _id: userId },
        {
            $set: { refreshTokens: [] }
        }
    );
};

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

const hasRole = (user, role) => {
    return user.role === role;
};

const hasAnyRole = (user, roles) => {
    return roles.includes(user.role);
};

const setPasswordResetToken = async (userId, hashedToken, expires) => {
    return await User.updateOne(
        { _id: userId },
        {
            passwordResetToken: hashedToken,
            passwordResetExpires: expires
        }
    );
};


const setEmailVerificationToken = async (userId, hashedToken, expires) => {
    return await User.updateOne(
        { _id: userId },
        {
            emailVerificationToken: hashedToken,
            emailVerificationExpires: expires
        }
    );
};

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