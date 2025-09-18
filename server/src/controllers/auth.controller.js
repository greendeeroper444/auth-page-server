const User = require('../models/user.model');
const { generateTokenPair, verifyToken, createPasswordResetToken, createEmailVerificationToken, hashToken } = require('../helpers/authHelpers');
const { 
    findUserByEmailOrUsername, 
    findUserForLogin, 
    handleFailedLoginAttempt, 
    resetLoginAttempts, 
    addLoginHistory,
    addRefreshToken,
    removeRefreshToken,
    removeAllRefreshTokens,
    setPasswordResetToken,
    setEmailVerificationToken,
    verifyEmail
} = require('../helpers/userHelpers');
const { validateRegistrationData, validateLoginData } = require('../helpers/validationHelpers');
const { getClientInfo, sanitizeInput, isCommonPassword } = require('../helpers/securityHelpers');
const { sendEmailVerification, sendPasswordReset, sendWelcomeEmail } = require('../helpers/emailHelpers');
const { getRefreshTokenConfig, getAccessTokenConfig, getCookieConfig } = require('../helpers/cookieHelpers');


/**
 * register new user
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const register = async (req, res) => {
    try {
        //validate input data
        const { isValid, errors } = validateRegistrationData(req.body);
        if (!isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        const { firstName, lastName, email, username, password, phone, dateOfBirth } = req.body;

        //check if user already exists
        const existingUser = await findUserByEmailOrUsername(email);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'User already exists with this email or username'
            });
        }

        //check for common passwords
        if (isCommonPassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Please choose a stronger password'
            });
        }

        //create new user
        const user = new User({
            firstName: sanitizeInput(firstName),
            lastName: sanitizeInput(lastName),
            email: email.toLowerCase(),
            username: sanitizeInput(username),
            password,
            phone: phone ? sanitizeInput(phone) : undefined,
            dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined
        });

        await user.save();

        //generate email verification token
        const { plainToken, hashedToken, expires } = createEmailVerificationToken();
        await setEmailVerificationToken(user._id, hashedToken, expires);

        //send verification email
        const emailSent = await sendEmailVerification(user.email, user.firstName, plainToken);
        
        // get client info and log registration
        const clientInfo = getClientInfo(req);
        await addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, true);

        res.status(201).json({
            success: true,
            message: 'User registered successfully. Please check your email to verify your account.',
            data: {
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
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        
        //handle duplicate key errors
        if (error.code === 11000) {
            const field = Object.keys(error.keyValue)[0];
            return res.status(409).json({
                success: false,
                message: `${field} already exists`
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error during registration'
        });
    }
};

/**
 * login user
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const login = async (req, res) => {
    try {
        //validate input data
        const { isValid, errors } = validateLoginData(req.body);
        if (!isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        const { identifier, password, rememberMe = false } = req.body;
        const clientInfo = getClientInfo(req);
        const isProduction = process.env.NODE_ENV === 'production';

        //find user with password field
        const user = await findUserForLogin(identifier);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        //check if account is locked
        if (user.isLocked) {
            await addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, false);
            return res.status(423).json({
                success: false,
                message: 'Account is temporarily locked due to too many failed login attempts'
            });
        }

        //check if account is active
        if (!user.isActive || user.accountStatus === 'suspended') {
            return res.status(403).json({
                success: false,
                message: 'Account is not active'
            });
        }

        //verify password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            await handleFailedLoginAttempt(user);
            await addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, false);
            
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        //reset login attempts on successful login
        await resetLoginAttempts(user._id);

        //generate tokens
        const tokens = generateTokenPair(user);
        
        //store refresh token
        await addRefreshToken(user._id, tokens.refreshToken);

        //log successful login
        await addLoginHistory(user._id, clientInfo.ip, clientInfo.userAgent, true);

        //set cookies
        const accessTokenCookie = getAccessTokenConfig(isProduction);
        const refreshTokenCookie = rememberMe ? 
            getRefreshTokenConfig(isProduction) : 
            {
                ...getCookieConfig(isProduction),
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            };

        console.log('Setting cookies with config:', {
            accessToken: accessTokenCookie,
            refreshToken: refreshTokenCookie
        });

        res.cookie('accessToken', tokens.accessToken, accessTokenCookie);
        res.cookie('refreshToken', tokens.refreshToken, refreshTokenCookie);

        console.log('Cookies set successfully');

        res.json({
            success: true,
            message: 'Login successful',
            data: {
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
                }
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during login'
        });
    }
};

/**
 * refresh access token
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        const isProduction = process.env.NODE_ENV === 'production';
        
        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                message: 'Refresh token is required'
            });
        }

        //verify refresh token
        const decoded = verifyToken(refreshToken);
        if (!decoded || decoded.tokenType !== 'refresh') {
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        //find user and check if refresh token exists
        const user = await User.findOne({
            _id: decoded.id,
            'refreshTokens.token': refreshToken
        });

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        //check if user is still active
        if (!user.isActive || user.accountStatus === 'suspended') {
            await removeRefreshToken(user._id, refreshToken);
            //clear cookies
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            return res.status(403).json({
                success: false,
                message: 'Account is not active'
            });
        }

        //generate new tokens
        const tokens = generateTokenPair(user);

        //replace old refresh token with new one
        await removeRefreshToken(user._id, refreshToken);
        await addRefreshToken(user._id, tokens.refreshToken);

        //update cookies
        res.cookie('accessToken', tokens.accessToken, getAccessTokenConfig(isProduction));
        res.cookie('refreshToken', tokens.refreshToken, getRefreshTokenConfig(isProduction));

        res.json({
            success: true,
            message: 'Token refreshed successfully'
        });

    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * logout user
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (refreshToken) {
            //remove refresh token from database
            const decoded = verifyToken(refreshToken);
            if (decoded) {
                await removeRefreshToken(decoded.id, refreshToken);
            }
        }

        //clear cookies
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');

        res.json({
            success: true,
            message: 'Logged out successfully'
        });

    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during logout'
        });
    }
};

/**
 * logout from all devices
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const logoutAll = async (req, res) => {
    try {
        const userId = req.user.id;

        //remove all refresh tokens
        await removeAllRefreshTokens(userId);

        //clear cookies
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');

        res.json({
            success: true,
            message: 'Logged out from all devices successfully'
        });

    } catch (error) {
        console.error('Logout all error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * verify email address
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const verifyEmailAddress = async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json({
                success: false,
                message: 'Verification token is required'
            });
        }

        //hash the token to compare with stored hash
        const hashedToken = hashToken(token);

        //verify email and update user
        const user = await verifyEmail(hashedToken);

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification token'
            });
        }

        //send welcome email
        await sendWelcomeEmail(user.email, user.firstName);

        res.json({
            success: true,
            message: 'Email verified successfully',
            data: {
                user: {
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    isEmailVerified: user.isEmailVerified,
                    accountStatus: user.accountStatus
                }
            }
        });

    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during email verification'
        });
    }
};

/**
 * resend email verification
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const resendEmailVerification = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            //don't reveal if user exists or not
            return res.json({
                success: true,
                message: 'If the email exists, a verification link has been sent'
            });
        }

        if (user.isEmailVerified) {
            return res.status(400).json({
                success: false,
                message: 'Email is already verified'
            });
        }

        //generate new verification token
        const { plainToken, hashedToken, expires } = createEmailVerificationToken();
        await setEmailVerificationToken(user._id, hashedToken, expires);

        //send verification email
        const emailSent = await sendEmailVerification(user.email, user.firstName, plainToken);

        res.json({
            success: true,
            message: 'Verification email sent',
            data: { emailSent }
        });

    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * request password reset
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const requestPasswordReset = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });

        //always return success to prevent email enumeration
        if (!user) {
            return res.json({
                success: true,
                message: 'If the email exists, a password reset link has been sent'
            });
        }

        //generate password reset token
        const { plainToken, hashedToken, expires } = createPasswordResetToken();
        await setPasswordResetToken(user._id, hashedToken, expires);

        //send password reset email
        const emailSent = await sendPasswordReset(user.email, user.firstName, plainToken);

        res.json({
            success: true,
            message: 'If the email exists, a password reset link has been sent',
            data: { emailSent }
        });

    } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * reset password
 * @param {Object} req - express request object
 * @param {Object} res - express response object
 */
const resetPassword = async (req, res) => {
    try {
        const { token, password } = req.body;

        if (!token || !password) {
            return res.status(400).json({
                success: false,
                message: 'Token and password are required'
            });
        }

        //validate password
        const { validatePassword } = require('../helpers/validationHelpers');
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'Password validation failed',
                errors: { password: passwordValidation.errors }
            });
        }

        //check for common passwords
        if (isCommonPassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Please choose a stronger password'
            });
        }

        //hash the token
        const hashedToken = hashToken(token);

        //find user with valid reset token
        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        }).select('+passwordResetToken +passwordResetExpires');

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }

        //update password and clear reset token
        user.password = password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        user.passwordChangedAt = new Date();

        await user.save();

        //remove all refresh tokens (logout from all devices)
        await removeAllRefreshTokens(user._id);

        res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during password reset'
        });
    }
};

module.exports = {
    register,
    login,
    refreshToken,
    logout,
    logoutAll,
    verifyEmailAddress,
    resendEmailVerification,
    requestPasswordReset,
    resetPassword
};