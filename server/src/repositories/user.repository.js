const BaseRepository = require('./base.repository');
const User = require('../models/user.model');

class UserRepository extends BaseRepository {
    constructor() {
        super(User);
    }

    async getUserProfile(userId) {
        try {
            return await this.model.findById(userId).select('-refreshTokens -__v');
        } catch (error) {
            throw new Error(`Error getting user profile: ${error.message}`);
        }
    }

   
    async updateProfile(userId, updates) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                { $set: updates },
                { new: true, runValidators: true }
            ).select('-refreshTokens -__v');
        } catch (error) {
            throw new Error(`Error updating user profile: ${error.message}`);
        }
    }

    async getUserWithPassword(userId) {
        try {
            return await this.model.findById(userId).select('+password');
        } catch (error) {
            throw new Error(`Error getting user with password: ${error.message}`);
        }
    }

    async updatePassword(userId, newPassword) {
        try {
            const user = await this.model.findById(userId).select('+password');
            if (!user) {
                throw new Error('User not found');
            }

            user.password = newPassword;
            user.passwordChangedAt = new Date();
            return await user.save();
        } catch (error) {
            throw new Error(`Error updating password: ${error.message}`);
        }
    }

    async softDeleteUser(userId, email, username) {
        try {
            const timestamp = Date.now();
            return await this.model.findByIdAndUpdate(
                userId,
                {
                    isActive: false,
                    accountStatus: 'inactive',
                    email: `deleted_${timestamp}_${email}`,
                    username: `deleted_${timestamp}_${username}`
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error soft deleting user: ${error.message}`);
        }
    }

    async getPaginatedUsers(searchQuery, sortObject, skip, limit) {
        try {
            return await this.model.find(searchQuery)
                .sort(sortObject)
                .skip(skip)
                .limit(limit)
                .select('-refreshTokens -__v');
        } catch (error) {
            throw new Error(`Error getting paginated users: ${error.message}`);
        }
    }

    async getUserForAdmin(userId) {
        try {
            return await this.model.findById(userId).select('-refreshTokens -__v');
        } catch (error) {
            throw new Error(`Error getting user for admin: ${error.message}`);
        }
    }

    async updateUserRole(userId, updates) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                { $set: updates },
                { new: true, runValidators: true }
            ).select('-refreshTokens -__v');
        } catch (error) {
            throw new Error(`Error updating user role: ${error.message}`);
        }
    }

    async updateAccountStatus(userId, updates) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                { $set: updates },
                { new: true }
            ).select('-refreshTokens -__v');
        } catch (error) {
            throw new Error(`Error updating account status: ${error.message}`);
        }
    }

    async getUserStatsData(userId) {
        try {
            return await this.model.findById(userId)
                .select('loginHistory createdAt lastLogin accountStatus role');
        } catch (error) {
            throw new Error(`Error getting user stats data: ${error.message}`);
        }
    }

    async getUserLoginHistory(userId) {
        try {
            return await this.model.findById(userId).select('loginHistory');
        } catch (error) {
            throw new Error(`Error getting login history: ${error.message}`);
        }
    }

    buildSearchQuery(search, role, status) {
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

        return searchQuery;
    }

    buildSortObject(sortBy = 'createdAt', sortOrder = 'desc') {
        const sortObject = {};
        sortObject[sortBy] = sortOrder === 'desc' ? -1 : 1;
        return sortObject;
    }

    async removeAllRefreshTokens(userId) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                { $set: { refreshTokens: [] } },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error removing refresh tokens: ${error.message}`);
        }
    }

    async getUsersCount(searchQuery) {
        try {
            return await this.model.countDocuments(searchQuery);
        } catch (error) {
            throw new Error(`Error counting users: ${error.message}`);
        }
    }
}

module.exports = UserRepository;