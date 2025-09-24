const BaseService = require('./base.service');
const UserRepository = require('../repositories/user.repository');
const { validateProfileUpdateData, validatePassword } = require('../helpers/validationHelpers');
const { sanitizeInput, maskSensitiveData, isCommonPassword } = require('../helpers/securityHelpers');
const { hasPermission, hasRole, getUserStats } = require('../helpers/userHelpers');

class UserService extends BaseService {
    constructor() {
        const userRepository = new UserRepository();
        super(userRepository);
        this.userRepository = userRepository;
    }

    async getProfile(userId) {
        try {
            const user = await this.userRepository.getUserProfile(userId);
            if (!user) {
                throw new Error('User not found');
            }

            return {
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
            };
        } catch (error) {
            this.handleError(error, 'get profile');
        }
    }

    async updateProfile(userId, profileData) {
        try {
            const { isValid, errors } = validateProfileUpdateData(profileData);
            if (!isValid) {
                throw new Error(`Validation failed: ${JSON.stringify(errors)}`);
            }

            const allowedUpdates = [
                'firstName', 'lastName', 'phone', 'dateOfBirth', 
                'address', 'avatar', 'preferences'
            ];

            const updates = {};
            Object.keys(profileData).forEach(key => {
                if (allowedUpdates.includes(key) && profileData[key] !== undefined) {
                    if (typeof profileData[key] === 'string') {
                        updates[key] = sanitizeInput(profileData[key]);
                    } else {
                        updates[key] = profileData[key];
                    }
                }
            });

            if (Object.keys(updates).length === 0) {
                throw new Error('No valid fields to update');
            }

            const user = await this.userRepository.updateProfile(userId, updates);
            if (!user) {
                throw new Error('User not found');
            }

            return {
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
            };
        } catch (error) {
            this.handleError(error, 'update profile');
        }
    }

    async changePassword(userId, currentPassword, newPassword) {
        try {
            if (!currentPassword || !newPassword) {
                throw new Error('Current password and new password are required');
            }

            const user = await this.userRepository.getUserWithPassword(userId);
            if (!user) {
                throw new Error('User not found');
            }

            const isCurrentPasswordValid = await user.comparePassword(currentPassword);
            if (!isCurrentPasswordValid) {
                throw new Error('Current password is incorrect');
            }

            const passwordValidation = validatePassword(newPassword);
            if (!passwordValidation.isValid) {
                throw new Error(`New password validation failed: ${JSON.stringify(passwordValidation.errors)}`);
            }

            if (isCommonPassword(newPassword)) {
                throw new Error('Please choose a stronger password');
            }

            const isSamePassword = await user.comparePassword(newPassword);
            if (isSamePassword) {
                throw new Error('New password must be different from current password');
            }

            await this.userRepository.updatePassword(userId, newPassword);

            await this.userRepository.removeAllRefreshTokens(userId);

            return { message: 'Password changed successfully. Please log in again.' };
        } catch (error) {
            this.handleError(error, 'change password');
        }
    }

    async getUserStats(userId) {
        try {
            const stats = await getUserStats(userId);
            if (!stats) {
                throw new Error('User not found');
            }

            return { stats };
        } catch (error) {
            this.handleError(error, 'get user stats');
        }
    }

    async getLoginHistory(userId, page = 1, limit = 10) {
        try {
            const user = await this.userRepository.getUserLoginHistory(userId);
            if (!user) {
                throw new Error('User not found');
            }

    
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

            return {
                loginHistory: maskedHistory,
                pagination: {
                    currentPage: parseInt(page),
                    limit: parseInt(limit),
                    total: user.loginHistory.length,
                    totalPages: Math.ceil(user.loginHistory.length / limit)
                }
            };
        } catch (error) {
            this.handleError(error, 'get login history');
        }
    }

    async deleteAccount(userId, password, confirmation) {
        try {
            if (!password || confirmation !== 'DELETE') {
                throw new Error('Password and confirmation ("DELETE") are required');
            }

            const user = await this.userRepository.getUserWithPassword(userId);
            if (!user) {
                throw new Error('User not found');
            }

            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                throw new Error('Password is incorrect');
            }

            await this.userRepository.softDeleteUser(userId, user.email, user.username);

            return { message: 'Account deleted successfully' };
        } catch (error) {
            this.handleError(error, 'delete account');
        }
    }

    async getAllUsers(user, filters) {
        try {

            if (!hasRole(user, 'admin') && !hasRole(user, 'superadmin')) {
                throw new Error('Access denied. Admin role required.');
            }

            const {
                page = 1,
                limit = 20,
                search = '',
                role = '',
                status = '',
                sortBy = 'createdAt',
                sortOrder = 'desc'
            } = filters;

            const searchQuery = this.userRepository.buildSearchQuery(search, role, status);
            const sortObject = this.userRepository.buildSortObject(sortBy, sortOrder);

            const skip = (parseInt(page) - 1) * parseInt(limit);

            const [users, totalUsers] = await Promise.all([
                this.userRepository.getPaginatedUsers(searchQuery, sortObject, skip, parseInt(limit)),
                this.userRepository.getUsersCount(searchQuery)
            ]);

            return {
                users,
                pagination: {
                    currentPage: parseInt(page),
                    limit: parseInt(limit),
                    total: totalUsers,
                    totalPages: Math.ceil(totalUsers / parseInt(limit))
                }
            };
        } catch (error) {
            this.handleError(error, 'get all users');
        }
    }

    async getUserById(currentUser, userId) {
        try {
            if (!hasPermission(currentUser, 'manage_users')) {
                throw new Error('Access denied. User management permission required.');
            }

            const user = await this.userRepository.getUserForAdmin(userId);
            if (!user) {
                throw new Error('User not found');
            }

            const stats = await getUserStats(userId);

            return {
                user,
                stats
            };
        } catch (error) {
            this.handleError(error, 'get user by ID');
        }
    }

    async updateUserRole(currentUser, userId, role, permissions) {
        try {
            if (!hasRole(currentUser, 'superadmin') && !hasPermission(currentUser, 'manage_users')) {
                throw new Error('Access denied. Insufficient permissions.');
            }

            const validRoles = ['user', 'admin', 'moderator', 'superadmin'];
            if (role && !validRoles.includes(role)) {
                throw new Error('Invalid role specified');
            }

            if (role === 'superadmin' && !hasRole(currentUser, 'superadmin')) {
                throw new Error('Only superadmin can assign superadmin role');
            }

            if (userId === currentUser.id && currentUser.role === 'superadmin' && role !== 'superadmin') {
                throw new Error('Cannot change your own superadmin role');
            }

            const updates = {};
            if (role) updates.role = role;
            if (permissions) updates.permissions = permissions;

            const user = await this.userRepository.updateUserRole(userId, updates);
            if (!user) {
                throw new Error('User not found');
            }

            console.log(`User role updated: ${currentUser.email} changed ${user.email} role to ${role}`);

            return { user };
        } catch (error) {
            this.handleError(error, 'update user role');
        }
    }

    async updateAccountStatus(currentUser, userId, accountStatus, isActive) {
        try {
            if (!hasPermission(currentUser, 'manage_users')) {
                throw new Error('Access denied. User management permission required.');
            }

            const validStatuses = ['active', 'inactive', 'suspended', 'pending'];
            if (accountStatus && !validStatuses.includes(accountStatus)) {
                throw new Error('Invalid account status');
            }

            if (userId === currentUser.id && (accountStatus === 'suspended' || isActive === false)) {
                throw new Error('Cannot suspend your own account');
            }

            const updates = {};
            if (accountStatus !== undefined) updates.accountStatus = accountStatus;
            if (isActive !== undefined) updates.isActive = isActive;

            const user = await this.userRepository.updateAccountStatus(userId, updates);
            if (!user) {
                throw new Error('User not found');
            }

            if (accountStatus === 'suspended' || isActive === false) {
                await this.userRepository.removeAllRefreshTokens(userId);
            }

            const newStatus = accountStatus || (isActive ? 'active' : 'inactive');
            console.log(`Account status updated: ${currentUser.email} changed ${user.email} status to ${newStatus}`);

            return { user };
        } catch (error) {
            this.handleError(error, 'update account status');
        }
    }
}

module.exports = UserService;