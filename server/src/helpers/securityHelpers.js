const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

/**
 * generate secure random string
 * @param {Number} length - length of random string
 * @returns {String} random string
 */
const generateSecureRandom = (length = 32) => {
    return crypto.randomBytes(length).toString('hex');
};

/**
 * generate cryptographically secure random number
 * @param {Number} min - minimum value
 * @param {Number} max - maximum value
 * @returns {Number} random number
 */
const generateSecureRandomNumber = (min = 0, max = 999999) => {
    const range = max - min + 1;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8);
    const maxValue = Math.pow(256, bytesNeeded);
    const randomBytes = crypto.randomBytes(bytesNeeded);
    const randomValue = randomBytes.readUIntBE(0, bytesNeeded);
    
    return min + (randomValue % range);
};

/**
 * hash sensitive data
 * @param {String} data - data to hash
 * @param {String} salt - salt (optional)
 * @returns {Object} hash result with salt
 */
const hashSensitiveData = (data, salt = null) => {
    const usedSalt = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(data, usedSalt, 10000, 64, 'sha512').toString('hex');
    
    return {
        hash,
        salt: usedSalt
    };
};

/**
 * verify hashed data
 * @param {String} data - original data
 * @param {String} hash - hash to verify against
 * @param {String} salt -salt used for hashing
 * @returns {Boolean} verification result
 */
const verifySensitiveData = (data, hash, salt) => {
    const newHash = crypto.pbkdf2Sync(data, salt, 10000, 64, 'sha512').toString('hex');
    return hash === newHash;
};

/**
 * generate 2FA backup codes
 * @param {Number} count - number of codes to generate
 * @returns {Array} array of backup codes
 */
const generateBackupCodes = (count = 10) => {
    const codes = [];
    for (let i = 0; i < count; i++) {
        //generate 8-digit codes
        const code = generateSecureRandomNumber(10000000, 99999999).toString();
        codes.push({
            code,
            used: false
        });
    }
    return codes;
};

/**
 * sanitize user input to prevent XSS
 * @param {String} input - user input
 * @returns {String} sanitized input
 */
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    
    return input
        .replace(/[<>]/g, '') //remove < and >
        .replace(/javascript:/gi, '') //remove javascript: protocol
        .replace(/on\w+=/gi, '') //remove event handlers
        .trim();
};

/**
 * check for common SQL injection patterns
 * @param {String} input - user input
 * @returns {Boolean} contains suspicious patterns
 */
const containsSQLInjection = (input) => {
    if (typeof input !== 'string') return false;
    
    const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
        /(--|#|\/\*|\*\/)/,
        /('|(\\x27)|(\\x2D\\x2D))/,
        /(;|\s|^)(\s)*(or|and)\s+(1|true)/i
    ];
    
    return sqlPatterns.some(pattern => pattern.test(input));
};

/**
 * rate limiting middleware for login attempts
 */
const loginRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, //15 minutes
    max: 5, //limit each IP to 5 login requests per windowMs
    message: {
        error: 'Too many login attempts, please try again later',
        retryAfter: 15 * 60 //15 minutes in seconds
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        //use IP + user identifier for more specific limiting
        const identifier = req.body.identifier || req.body.email || req.body.username || '';
        return `${req.ip}-${identifier}`;
    }
});

/**
 * rate limiting middleware for password reset
 */
const passwordResetRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, //3 password reset requests per hour per IP
    message: {
        error: 'Too many password reset attempts, please try again later',
        retryAfter: 60 * 60
    },
    standardHeaders: true,
    legacyHeaders: false
});

/**
 * rate limiting middleware for email verification
 */
const emailVerificationRateLimit = rateLimit({
    windowMs: 5 * 60 * 1000, //5 minutes
    max: 3, //3 email verification requests per 5 minutes
    message: {
        error: 'Too many verification email requests, please wait',
        retryAfter: 5 * 60
    }
});

/**
 * slow down middleware for repeated requests
 * fixed for express-slow-down v2 compatibility
 */
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, //15 minutes
    delayAfter: 2, //allow 2 requests per windowMs without delay
    delayMs: () => 500, //fixed: function that returns delay amount
    maxDelayMs: 20000, //maximum delay of 20 seconds
    validate: {
        delayMs: false //disable the warning message
    }
});

/**
 * extract client information from request
 * @param {Object} req - express request object
 * @returns {Object} client information
 */
const getClientInfo = (req) => {
    return {
        ip: req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'],
        userAgent: req.get('User-Agent') || 'Unknown',
        timestamp: new Date(),
        referer: req.get('Referer') || null
    };
};

/**
 * check if IP is from suspicious location/proxy
 * @param {String} ip - IP address
 * @returns {Object} IP analysis result
 */
const analyzeIP = (ip) => {
    //basic IP validation and analysis
    const isPrivate = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);
    const isLocalhost = ip === '127.0.0.1' || ip === '::1';
    
    //check for common proxy/VPN patterns (basic check)
    const suspiciousPatterns = [
        /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/,
        /^169\.254\./, //link-local
        /^224\./, //multicast
    ];
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(ip));
    
    return {
        ip,
        isPrivate,
        isLocalhost,
        isSuspicious: isSuspicious && !isPrivate && !isLocalhost,
        riskLevel: isSuspicious ? 'medium' : 'low'
    };
};

/**
 * generate CSRF token
 * @returns {String} CSRF token
 */
const generateCSRFToken = () => {
    return crypto.randomBytes(32).toString('base64');
};

/**
 * verify CSRF token
 * @param {String} token - token to verify
 * @param {String} sessionToken - token from session
 * @returns {Boolean} token is valid
 */
const verifyCSRFToken = (token, sessionToken) => {
    if (!token || !sessionToken) return false;
    return crypto.timingSafeEqual(
        Buffer.from(token, 'base64'),
        Buffer.from(sessionToken, 'base64')
    );
};

/**
 * mask sensitive data for logging
 * @param {String} data - sensitive data
 * @param {Number} visibleChars - number of visible characters
 * @returns {String} masked data
 */
const maskSensitiveData = (data, visibleChars = 4) => {
    if (!data || typeof data !== 'string') return '***';
    
    if (data.length <= visibleChars) {
        return '*'.repeat(data.length);
    }
    
    const visible = data.slice(0, visibleChars);
    const masked = '*'.repeat(data.length - visibleChars);
    
    return visible + masked;
};

/**
 * check password against common passwords list
 * @param {String} password - password to check
 * @returns {Boolean} is common password
 */
const isCommonPassword = (password) => {
    const commonPasswords = [
        '123456', 'password', '123456789', '12345678', '12345',
        '1234567', '1234567890', 'qwerty', 'abc123', 'million2',
        '000000', '1234', 'iloveyou', 'aaron431', 'password1',
        'qqww1122', '123', 'omgpop', 'password123', 'admin'
    ];
    
    return commonPasswords.includes(password.toLowerCase());
};

/**
 * security headers middleware
 * @param {Object} req - express request
 * @param {Object} res - express response
 * @param {Function} next - next middleware
 */
const securityHeaders = (req, res, next) => {
    //remove server information
    res.removeHeader('X-Powered-By');
    
    //security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    //HSTS (only in production with HTTPS)
    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    
    next();
};

module.exports = {
    generateSecureRandom,
    generateSecureRandomNumber,
    hashSensitiveData,
    verifySensitiveData,
    generateBackupCodes,
    sanitizeInput,
    containsSQLInjection,
    loginRateLimit,
    passwordResetRateLimit,
    emailVerificationRateLimit,
    speedLimiter,
    getClientInfo,
    analyzeIP,
    generateCSRFToken,
    verifyCSRFToken,
    maskSensitiveData,
    isCommonPassword,
    securityHeaders
};