const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config/environment');

/**
 * generate jwt access token
 * @param {Object} user - user object
 * @returns {String} jwt token
 */
const generateAccessToken = (user) => {
    return jwt.sign(
        { 
            id: user._id,
            email: user.email,
            role: user.role 
        },
        config.JWT_SECRET,
        { 
            expiresIn: '15m',
            issuer: 'auth_secure',
            audience: 'auth_secure_users'
        }
    );
};

/**
 * generate JWT refresh token
 * @param {Object} user - user object
 * @returns {String} jwt refresh token
 */
const generateRefreshToken = (user) => {
    return jwt.sign(
        { 
            id: user._id,
            tokenType: 'refresh'
        },
        config.JWT_SECRET,
        { 
            expiresIn: '7d',
            issuer: 'auth_secure',
            audience: 'auth_secure_users'
        }
    );
};

/**
 * generate both access and refresh tokens
 * @param {Object} user - user object
 * @returns {Object} object containing both tokens
 */
const generateTokenPair = (user) => {
    return {
        accessToken: generateAccessToken(user),
        refreshToken: generateRefreshToken(user)
    };
};

/**
 * verify jwt token
 * @param {String} token - jwt token
 * @returns {Object|null} decoded token or null if invalid
 */
const verifyToken = (token) => {
    try {
        return jwt.verify(token, config.JWT_SECRET, {
            issuer: 'auth_secure',
            audience: 'auth_secure_users'
        });
    } catch (error) {
        return null;
    }
};

/**
 * create password reset token
 * @returns {Object} object containing plain token and hashed token
 */
const createPasswordResetToken = () => {
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
    
    return {
        plainToken: resetToken,
        hashedToken,
        expires: Date.now() + 10 * 60 * 1000 //10 minutes
    };
};

/**
 * create email verification token
 * @returns {Object} object containing plain token and hashed token
 */
const createEmailVerificationToken = () => {
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto
        .createHash('sha256')
        .update(verifyToken)
        .digest('hex');
    
    return {
        plainToken: verifyToken,
        hashedToken,
        expires: Date.now() + 24 * 60 * 60 * 1000 //24 hours
    };
};

/**
 * hash a plain token
 * @param {String} token - plain token
 * @returns {String} hashed token
 */
const hashToken = (token) => {
    return crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
};

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    generateTokenPair,
    verifyToken,
    createPasswordResetToken,
    createEmailVerificationToken,
    hashToken
};