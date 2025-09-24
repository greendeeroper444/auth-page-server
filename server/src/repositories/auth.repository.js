const BaseRepository = require('./base.repository');
const User = require('../models/user.model');

class AuthRepository extends BaseRepository {
    constructor() {
        super(User);
    }

    async findUserByEmailOrUsername(identifier) {
        try {
            return await this.model.findOne({
                $or: [
                    { email: identifier.toLowerCase() },
                    { username: identifier }
                ]
            });
        } catch (error) {
            throw new Error(`Error finding user by email or username: ${error.message}`);
        }
    }

    async findUserForLogin(identifier) {
        try {
            return await this.model.findOne({
                $or: [
                    { email: identifier.toLowerCase() },
                    { username: identifier }
                ]
            }).select('+password +failedLoginAttempts +lockUntil');
        } catch (error) {
            throw new Error(`Error finding user for login: ${error.message}`);
        }
    }

    async findUserWithRefreshToken(userId, refreshToken) {
        try {
            return await this.model.findOne({
                _id: userId,
                'refreshTokens.token': refreshToken
            });
        } catch (error) {
            throw new Error(`Error finding user with refresh token: ${error.message}`);
        }
    }

    async findUserByPasswordResetToken(hashedToken) {
        try {
            return await this.model.findOne({
                passwordResetToken: hashedToken,
                passwordResetExpires: { $gt: Date.now() }
            }).select('+passwordResetToken +passwordResetExpires');
        } catch (error) {
            throw new Error(`Error finding user by password reset token: ${error.message}`);
        }
    }

    async handleFailedLoginAttempt(user) {
        try {
            const updates = {
                $inc: { failedLoginAttempts: 1 }
            };

            //lock account after 5 failed attempts for 30 minutes
            if (user.failedLoginAttempts >= 4) {
                updates.lockUntil = Date.now() + 30 * 60 * 1000; //30 minutes
            }

            return await this.model.findByIdAndUpdate(
                user._id,
                updates,
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error handling failed login attempt: ${error.message}`);
        }
    }

    async resetLoginAttempts(userId) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                {
                    $unset: {
                        failedLoginAttempts: 1,
                        lockUntil: 1
                    },
                    lastLogin: new Date()
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error resetting login attempts: ${error.message}`);
        }
    }

    async addLoginHistory(userId, ipAddress, userAgent, success) {
        try {
            const loginRecord = {
                ipAddress,
                userAgent,
                success,
                timestamp: new Date()
            };

            return await this.model.findByIdAndUpdate(
                userId,
                {
                    $push: {
                        loginHistory: {
                            $each: [loginRecord],
                            $slice: -10 //keep only last 10 login attempts
                        }
                    }
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error adding login history: ${error.message}`);
        }
    }

    async addRefreshToken(userId, refreshToken) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                {
                    $push: {
                        refreshTokens: {
                            token: refreshToken,
                            createdAt: new Date()
                        }
                    }
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error adding refresh token: ${error.message}`);
        }
    }

    async removeRefreshToken(userId, refreshToken) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                {
                    $pull: {
                        refreshTokens: { token: refreshToken }
                    }
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error removing refresh token: ${error.message}`);
        }
    }

    async removeAllRefreshTokens(userId) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                {
                    $set: { refreshTokens: [] }
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error removing all refresh tokens: ${error.message}`);
        }
    }

    async setPasswordResetToken(userId, hashedToken, expires) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                {
                    passwordResetToken: hashedToken,
                    passwordResetExpires: expires
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error setting password reset token: ${error.message}`);
        }
    }

    async setEmailVerificationToken(userId, hashedToken, expires) {
        try {
            return await this.model.findByIdAndUpdate(
                userId,
                {
                    emailVerificationToken: hashedToken,
                    emailVerificationExpires: expires
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error setting email verification token: ${error.message}`);
        }
    }

    async verifyEmail(hashedToken) {
        try {
            return await this.model.findOneAndUpdate(
                {
                    emailVerificationToken: hashedToken,
                    emailVerificationExpires: { $gt: Date.now() }
                },
                {
                    $set: {
                        isEmailVerified: true,
                        emailVerifiedAt: new Date()
                    },
                    $unset: {
                        emailVerificationToken: 1,
                        emailVerificationExpires: 1
                    }
                },
                { new: true }
            );
        } catch (error) {
            throw new Error(`Error verifying email: ${error.message}`);
        }
    }

    async updatePasswordAndClearResetToken(userId, newPassword) {
        try {
            const user = await this.model.findById(userId).select('+passwordResetToken +passwordResetExpires');
            
            if (!user) {
                throw new Error('User not found');
            }

            user.password = newPassword;
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            user.passwordChangedAt = new Date();

            return await user.save();
        } catch (error) {
            throw new Error(`Error updating password: ${error.message}`);
        }
    }

    async getUserProfile(userId) {
        try {
            return await this.model.findById(userId).select('-password -refreshTokens -__v');
        } catch (error) {
            throw new Error(`Error getting user profile: ${error.message}`);
        }
    }
}

module.exports = AuthRepository;