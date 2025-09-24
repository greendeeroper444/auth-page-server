const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config/environment');

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

const generateTokenPair = (user) => {
    return {
        accessToken: generateAccessToken(user),
        refreshToken: generateRefreshToken(user)
    };
};

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