const User = require('../models/user.model');
const { 
    hasPermission, 
    hasRole, 
    getUserStats,
    removeAllRefreshTokens 
} = require('../helpers/userHelpers');
const { validateProfileUpdateData } = require('../helpers/validationHelpers');
const { sanitizeInput, maskSensitiveData } = require('../helpers/securityHelpers');

/**
 * get current user profile
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const getProfile = async (req, res) => {
    try {
        const userId = req.user.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            data: {
                user: {
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    fullName: user.fullName,
                    email: user.email,
                    username: user.username,
                    avatar: user.avatar,
                    phone: user.phone,
                    dateOfBirth: user.dateOfBirth,
                    address: user.address,
                    role: user.role,
                    permissions: user.permissions,
                    isEmailVerified: user.isEmailVerified,
                    accountStatus: user.accountStatus,
                    lastLogin: user.lastLogin,
                    preferences: user.preferences,
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt
                }
            }
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * update user profile
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const updateProfile = async (req, res) => {
    try {
        const userId = req.user.id;

        //validate input data
        const { isValid, errors } = validateProfileUpdateData(req.body);
        if (!isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        const allowedUpdates = [
            'firstName', 'lastName', 'phone', 'dateOfBirth', 
            'address', 'avatar', 'preferences'
        ];

        const updates = {};
        Object.keys(req.body).forEach(key => {
            if (allowedUpdates.includes(key) && req.body[key] !== undefined) {
                if (typeof req.body[key] === 'string') {
                    updates[key] = sanitizeInput(req.body[key]);
                } else {
                    updates[key] = req.body[key];
                }
            }
        });

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No valid fields to update'
            });
        }

        const user = await User.findByIdAndUpdate(
            userId,
            { $set: updates },
            { new: true, runValidators: true }
        );

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: {
                user: {
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    fullName: user.fullName,
                    email: user.email,
                    username: user.username,
                    avatar: user.avatar,
                    phone: user.phone,
                    dateOfBirth: user.dateOfBirth,
                    address: user.address,
                    preferences: user.preferences,
                    updatedAt: user.updatedAt
                }
            }
        });

    } catch (error) {
        console.error('Update profile error:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: 'Validation error',
                errors: Object.values(error.errors).map(err => err.message)
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * change user password
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const changePassword = async (req, res) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }

        //find user with password
        const user = await User.findById(userId).select('+password');
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        //verify current password
        const isCurrentPasswordValid = await user.comparePassword(currentPassword);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        //validate new password
        const { validatePassword } = require('../helpers/validationHelpers');
        const { isCommonPassword } = require('../helpers/securityHelpers');
        
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'New password validation failed',
                errors: { password: passwordValidation.errors }
            });
        }

        if (isCommonPassword(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'Please choose a stronger password'
            });
        }

        //check if new password is same as current
        const isSamePassword = await user.comparePassword(newPassword);
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: 'New password must be different from current password'
            });
        }

        //update password
        user.password = newPassword;
        user.passwordChangedAt = new Date();
        await user.save();

        //remove all refresh tokens (logout from all devices)
        await removeAllRefreshTokens(userId);

        res.json({
            success: true,
            message: 'Password changed successfully. Please log in again.'
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * get user statistics
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const getStats = async (req, res) => {
    try {
        const userId = req.user.id;

        const stats = await getUserStats(userId);
        if (!stats) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            data: { stats }
        });

    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * get login history
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const getLoginHistory = async (req, res) => {
    try {
        const userId = req.user.id;
        const { limit = 10, page = 1 } = req.query;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        //get paginated login history
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + parseInt(limit);
        const loginHistory = user.loginHistory
            .sort((a, b) => b.timestamp - a.timestamp)
            .slice(startIndex, endIndex);

        //mask ip addresses for security
        const maskedHistory = loginHistory.map(entry => ({
            ...entry.toObject(),
            ip: maskSensitiveData(entry.ip, 7) //show first 7 characters of IP
        }));

        res.json({
            success: true,
            data: {
                loginHistory: maskedHistory,
                pagination: {
                    currentPage: parseInt(page),
                    limit: parseInt(limit),
                    total: user.loginHistory.length,
                    totalPages: Math.ceil(user.loginHistory.length / limit)
                }
            }
        });

    } catch (error) {
        console.error('Get login history error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * delete user account
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const deleteAccount = async (req, res) => {
    try {
        const userId = req.user.id;
        const { password, confirmation } = req.body;

        if (!password || confirmation !== 'DELETE') {
            return res.status(400).json({
                success: false,
                message: 'Password and confirmation ("DELETE") are required'
            });
        }

        //find user with password
        const user = await User.findById(userId).select('+password');
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        //verify password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(400).json({
                success: false,
                message: 'Password is incorrect'
            });
        }

        //instead of hard delete, mark as inactive (soft delete)
        //this preserves data integrity and audit trails
        await User.findByIdAndUpdate(userId, {
            isActive: false,
            accountStatus: 'inactive',
            email: `deleted_${Date.now()}_${user.email}`, //prevent email conflicts
            username: `deleted_${Date.now()}_${user.username}` //prevent username conflicts
        });

        res.json({
            success: true,
            message: 'Account deleted successfully'
        });

    } catch (error) {
        console.error('Delete account error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * get all users (Admin only)
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const getAllUsers = async (req, res) => {
    try {
        //check if user has admin permissions
        if (!hasRole(req.user, 'admin') && !hasRole(req.user, 'superadmin')) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin role required.'
            });
        }

        const { 
            page = 1, 
            limit = 20, 
            search = '', 
            role = '', 
            status = '',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        //build search query
        const searchQuery = {};
        
        if (search) {
            searchQuery.$or = [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { username: { $regex: search, $options: 'i' } }
            ];
        }

        if (role) {
            searchQuery.role = role;
        }

        if (status) {
            searchQuery.accountStatus = status;
        }

        //build sort object
        const sortObject = {};
        sortObject[sortBy] = sortOrder === 'desc' ? -1 : 1;

        //calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        //get users with pagination
        const users = await User.find(searchQuery)
            .sort(sortObject)
            .skip(skip)
            .limit(parseInt(limit))
            .select('-refreshTokens');

        //get total count for pagination
        const totalUsers = await User.countDocuments(searchQuery);

        res.json({
            success: true,
            data: {
                users,
                pagination: {
                    currentPage: parseInt(page),
                    limit: parseInt(limit),
                    total: totalUsers,
                    totalPages: Math.ceil(totalUsers / parseInt(limit))
                }
            }
        });

    } catch (error) {
        console.error('Get all users error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * get user by ID (Admin only)
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const getUserById = async (req, res) => {
    try {
        //check permissions
        if (!hasPermission(req.user, 'manage_users')) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. User management permission required.'
            });
        }

        const { userId } = req.params;

        const user = await User.findById(userId).select('-refreshTokens');
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        //get user statistics
        const stats = await getUserStats(userId);

        res.json({
            success: true,
            data: {
                user,
                stats
            }
        });

    } catch (error) {
        console.error('Get user by ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * update user role (Admin only)
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const updateUserRole = async (req, res) => {
    try {
        //check if user has permission to manage users
        if (!hasRole(req.user, 'superadmin') && !hasPermission(req.user, 'manage_users')) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Insufficient permissions.'
            });
        }

        const { userId } = req.params;
        const { role, permissions } = req.body;

        //validate role
        const validRoles = ['user', 'admin', 'moderator', 'superadmin'];
        if (role && !validRoles.includes(role)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid role specified'
            });
        }

        //only superadmin can assign superadmin role
        if (role === 'superadmin' && !hasRole(req.user, 'superadmin')) {
            return res.status(403).json({
                success: false,
                message: 'Only superadmin can assign superadmin role'
            });
        }

        //prevent self-demotion from superadmin
        if (userId === req.user.id && req.user.role === 'superadmin' && role !== 'superadmin') {
            return res.status(400).json({
                success: false,
                message: 'Cannot change your own superadmin role'
            });
        }

        const updates = {};
        if (role) updates.role = role;
        if (permissions) updates.permissions = permissions;

        const user = await User.findByIdAndUpdate(
            userId,
            { $set: updates },
            { new: true, runValidators: true }
        ).select('-refreshTokens');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        //log the role change
        console.log(`User role updated: ${req.user.email} changed ${user.email} role to ${role}`);

        res.json({
            success: true,
            message: 'User role updated successfully',
            data: { user }
        });

    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * update user account status (Admin only)
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const updateAccountStatus = async (req, res) => {
    try {
        //check permissions
        if (!hasPermission(req.user, 'manage_users')) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. User management permission required.'
            });
        }

        const { userId } = req.params;
        const { accountStatus, isActive } = req.body;

        //validate account status
        const validStatuses = ['active', 'inactive', 'suspended', 'pending'];
        if (accountStatus && !validStatuses.includes(accountStatus)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid account status'
            });
        }

        //prevent self-suspension
        if (userId === req.user.id && (accountStatus === 'suspended' || isActive === false)) {
            return res.status(400).json({
                success: false,
                message: 'Cannot suspend your own account'
            });
        }

        const updates = {};
        if (accountStatus !== undefined) updates.accountStatus = accountStatus;
        if (isActive !== undefined) updates.isActive = isActive;

        const user = await User.findByIdAndUpdate(
            userId,
            { $set: updates },
            { new: true }
        ).select('-refreshTokens');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        //if account is suspended or deactivated, remove all refresh tokens
        if (accountStatus === 'suspended' || isActive === false) {
            await removeAllRefreshTokens(userId);
        }

        //log the status change
        console.log(`Account status updated: ${req.user.email} changed ${user.email} status to ${accountStatus || (isActive ? 'active' : 'inactive')}`);

        res.json({
            success: true,
            message: 'Account status updated successfully',
            data: { user }
        });

    } catch (error) {
        console.error('Update account status error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

module.exports = {
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
};