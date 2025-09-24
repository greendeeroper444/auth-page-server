const BaseService = require('./base.service');
const AuthRepository = require('../repositories/auth.repository');
const { generateTokenPair, verifyToken, createPasswordResetToken, createEmailVerificationToken, hashToken } = require('../helpers/authHelpers');
const { validateRegistrationData, validateLoginData, validatePassword } = require('../validators/user.validator');
const { getClientInfo, sanitizeInput, isCommonPassword } = require('../helpers/securityHelpers');
const { sendEmailVerification, sendPasswordReset, sendWelcomeEmail } = require('../helpers/emailHelpers');

class AuthService extends BaseService {
    constructor() {
        const authRepository = new AuthRepository();
        super(authRepository);
        this.authRepository = authRepository;
    }

    async register(userData, req) {
        try {
            const { isValid, errors } = validateRegistrationData(userData);
            if (!isValid) {
                throw new Error(`Validation failed: ${JSON.stringify(errors)}`);
            }

            const { firstName, lastName, email, username, password, phone, dateOfBirth } = userData;

            const existingUser = await this.authRepository.findUserByEmailOrUsername(email);
            if (existingUser) {
                throw new Error('User already exists with this email or username');
            }

            if (isCommonPassword(password)) {
                throw new Error('Please choose a stronger password');
            }

            const newUserData = {
                firstName: sanitizeInput(firstName),
                lastName: sanitizeInput(lastName),
                email: email.toLowerCase(),
                username: sanitizeInput(username),
                password,
                phone: phone ? sanitizeInput(phone) : undefined,
                dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined
            };

            const user = await this.authRepository.create(newUserData);

            const { plainToken, hashedToken, expires } = createEmailVerificationToken();
            await this.authRepository.setEmailVerificationToken(user._id, hashedToken, expires);

            const emailSent = await sendEmailVerification(user.email, user.firstName, plainToken);

            const clientInfo = getClientInfo(req);
            await this.authRepository.addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, true);

            return {
                user: {
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    username: user.username,
                    isEmailVerified: user.isEmailVerified,
                    accountStatus: user.accountStatus
                },
                emailSent
            };
        } catch (error) {
            this.handleError(error, 'user registration');
        }
    }

    async login(loginData, req) {
        try {
            const { isValid, errors } = validateLoginData(loginData);
            if (!isValid) {
                throw new Error(`Validation failed: ${JSON.stringify(errors)}`);
            }

            const { identifier, password, rememberMe = false } = loginData;
            const clientInfo = getClientInfo(req);

            const user = await this.authRepository.findUserForLogin(identifier);
            if (!user) {
                throw new Error('Invalid credentials');
            }

            if (user.isLocked) {
                await this.authRepository.addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, false);
                throw new Error('Account is temporarily locked due to too many failed login attempts');
            }

            if (!user.isActive || user.accountStatus === 'suspended') {
                throw new Error('Account is not active');
            }

            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                await this.authRepository.handleFailedLoginAttempt(user);
                await this.authRepository.addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, false);
                throw new Error('Invalid credentials');
            }

            await this.authRepository.resetLoginAttempts(user._id);

            const tokens = generateTokenPair(user);

            await this.authRepository.addRefreshToken(user._id, tokens.refreshToken);

            await this.authRepository.addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, true);

            return {
                user: {
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    username: user.username,
                    role: user.role,
                    isEmailVerified: user.isEmailVerified,
                    accountStatus: user.accountStatus,
                    lastLogin: user.lastLogin
                },
                tokens,
                rememberMe
            };
        } catch (error) {
            this.handleError(error, 'user login');
        }
    }

    async refreshToken(refreshToken) {
        try {
            if (!refreshToken) {
                throw new Error('Refresh token is required');
            }

            const decoded = verifyToken(refreshToken);
            if (!decoded || decoded.tokenType !== 'refresh') {
                throw new Error('Invalid refresh token');
            }

            const user = await this.authRepository.findUserWithRefreshToken(decoded.id, refreshToken);
            if (!user) {
                throw new Error('Invalid refresh token');
            }

            if (!user.isActive || user.accountStatus === 'suspended') {
                await this.authRepository.removeRefreshToken(user._id, refreshToken);
                throw new Error('Account is not active');
            }

            const tokens = generateTokenPair(user);

            await this.authRepository.removeRefreshToken(user._id, refreshToken);
            await this.authRepository.addRefreshToken(user._id, tokens.refreshToken);

            return { tokens };
        } catch (error) {
            this.handleError(error, 'token refresh');
        }
    }

    async logout(refreshToken) {
        try {
            if (refreshToken) {
                const decoded = verifyToken(refreshToken);
                if (decoded) {
                    await this.authRepository.removeRefreshToken(decoded.id, refreshToken);
                }
            }
            return { message: 'Logged out successfully' };
        } catch (error) {
            this.handleError(error, 'logout');
        }
    }

    async logoutAll(userId) {
        try {
            await this.authRepository.removeAllRefreshTokens(userId);
            return { message: 'Logged out from all devices successfully' };
        } catch (error) {
            this.handleError(error, 'logout all devices');
        }
    }

    async verifyEmail(token) {
        try {
            if (!token) {
                throw new Error('Verification token is required');
            }

            const hashedToken = hashToken(token);

            const user = await this.authRepository.verifyEmail(hashedToken);
            if (!user) {
                throw new Error('Invalid or expired verification token');
            }

            await sendWelcomeEmail(user.email, user.firstName);

            return {
                user: {
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    isEmailVerified: user.isEmailVerified,
                    accountStatus: user.accountStatus
                }
            };
        } catch (error) {
            this.handleError(error, 'email verification');
        }
    }

    async resendEmailVerification(email) {
        try {
            if (!email) {
                throw new Error('Email is required');
            }

            const user = await this.authRepository.findOne({ email: email.toLowerCase() });
            if (!user) {
                return { message: 'If the email exists, a verification link has been sent' };
            }

            if (user.isEmailVerified) {
                throw new Error('Email is already verified');
            }

            const { plainToken, hashedToken, expires } = createEmailVerificationToken();
            await this.authRepository.setEmailVerificationToken(user._id, hashedToken, expires);

            const emailSent = await sendEmailVerification(user.email, user.firstName, plainToken);

            return {
                message: 'Verification email sent',
                emailSent
            };
        } catch (error) {
            this.handleError(error, 'resend email verification');
        }
    }

    async requestPasswordReset(email) {
        try {
            if (!email) {
                throw new Error('Email is required');
            }

            const user = await this.authRepository.findOne({ email: email.toLowerCase() });
            
            if (!user) {
                return { message: 'If the email exists, a password reset link has been sent' };
            }

            const { plainToken, hashedToken, expires } = createPasswordResetToken();
            await this.authRepository.setPasswordResetToken(user._id, hashedToken, expires);

            const emailSent = await sendPasswordReset(user.email, user.firstName, plainToken);

            return {
                message: 'If the email exists, a password reset link has been sent',
                emailSent
            };
        } catch (error) {
            this.handleError(error, 'password reset request');
        }
    }

    async resetPassword(token, password) {
        try {
            if (!token || !password) {
                throw new Error('Token and password are required');
            }

            const passwordValidation = validatePassword(password);
            if (!passwordValidation.isValid) {
                throw new Error(`Password validation failed: ${JSON.stringify(passwordValidation.errors)}`);
            }

            if (isCommonPassword(password)) {
                throw new Error('Please choose a stronger password');
            }

            const hashedToken = hashToken(token);

            const user = await this.authRepository.findUserByPasswordResetToken(hashedToken);
            if (!user) {
                throw new Error('Invalid or expired reset token');
            }

            await this.authRepository.updatePasswordAndClearResetToken(user._id, password);

            await this.authRepository.removeAllRefreshTokens(user._id);

            return { message: 'Password reset successfully' };
        } catch (error) {
            this.handleError(error, 'password reset');
        }
    }

    async getUserProfile(userId) {
        try {
            const user = await this.authRepository.getUserProfile(userId);
            if (!user) {
                throw new Error('User not found');
            }
            return { user };
        } catch (error) {
            this.handleError(error, 'get user profile');
        }
    }

    async userExists(identifier) {
        try {
            const user = await this.authRepository.findUserByEmailOrUsername(identifier);
            return !!user;
        } catch (error) {
            this.handleError(error, 'check user existence');
        }
    }
}

module.exports = AuthService;