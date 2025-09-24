const User = require('../models/user.model');
const { verifyToken } = require('../helpers/authHelpers');
const { hasPermission, hasRole, hasAnyRole } = require('../helpers/userHelpers');

const authenticate = async (req, res, next) => {
    try {
        const accessToken = req.cookies.accessToken;
        
        if (!accessToken) {
            return res.status(401).json({
                success: false,
                message: 'Access token required'
            });
        }
       
        const decoded = verifyToken(accessToken);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired access token'
            });
        }

        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        //check if user is active
        if (!user.isActive || user.accountStatus === 'suspended') {
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            return res.status(403).json({
                success: false,
                message: 'Account is not active'
            });
        }

        //check if password was changed after token was issued
        const tokenIssuedAt = new Date(decoded.iat * 1000);
        if (user.passwordChangedAt && user.passwordChangedAt > tokenIssuedAt) {
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            return res.status(401).json({
                success: false,
                message: 'Password recently changed. Please log in again.'
            });
        }

        //attach user to request
        req.user = {
            id: user._id.toString(),
            email: user.email,
            role: user.role,
            permissions: user.permissions || [],
            isEmailVerified: user.isEmailVerified,
            accountStatus: user.accountStatus
        };

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid access token'
        });
    }
};


const optionalAuthenticate = async (req, res, next) => {
    try {
        //try cookies first, then fallback to authorization header for api compatibility
        let token = req.cookies.accessToken;
        
        if (!token) {
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                token = authHeader.substring(7);
            }
        }
        
        if (!token) {
            req.user = null;
            return next();
        }

        const decoded = verifyToken(token);
        
        if (!decoded) {
            req.user = null;
            return next();
        }

        const user = await User.findById(decoded.id);
        if (!user || !user.isActive || user.accountStatus === 'suspended') {
            req.user = null;
            return next();
        }

        req.user = {
            id: user._id.toString(),
            email: user.email,
            role: user.role,
            permissions: user.permissions || [],
            isEmailVerified: user.isEmailVerified,
            accountStatus: user.accountStatus
        };

        next();
    } catch (error) {
        req.user = null;
        next();
    }
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        if (!hasRole(req.user, role)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. ${role} role required.`
            });
        }

        next();
    };
};

const requireAnyRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        if (!hasAnyRole(req.user, roles)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. One of these roles required: ${roles.join(', ')}`
            });
        }

        next();
    };
};

const requirePermission = (permission) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        if (!hasPermission(req.user, permission)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. ${permission} permission required.`
            });
        }

        next();
    };
};

const requireEmailVerification = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }

    if (!req.user.isEmailVerified) {
        return res.status(403).json({
            success: false,
            message: 'Email verification required'
        });
    }

    next();
};

const requireOwnershipOrAdmin = (resourceUserIdField = 'userId') => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        const resourceUserId = req.params[resourceUserIdField] || req.body[resourceUserIdField];
        
        //allow if user owns the resource
        if (req.user.id === resourceUserId) {
            return next();
        }

        //allow if user is admin or has manage_users permission
        if (hasRole(req.user, 'admin') || hasRole(req.user, 'superadmin') || hasPermission(req.user, 'manage_users')) {
            return next();
        }

        return res.status(403).json({
            success: false,
            message: 'Access denied. You can only access your own resources.'
        });
    };
};


const checkUserRateLimit = (req, res, next) => {
    //enhanced rate limiting based on user role
    if (req.user) {
        //vip users (admin, superadmin) get higher limits
        if (hasAnyRole(req.user, ['admin', 'superadmin'])) {
            req.rateLimit = {
                limit: 1000, //higher limit for admins
                windowMs: 15 * 60 * 1000 //15 minutes
            };
        } else {
            req.rateLimit = {
                limit: 100, //standard limit for regular users
                windowMs: 15 * 60 * 1000
            };
        }
    }
    next();
};

const logUserActivity = (req, res, next) => {
    if (req.user) {
        const activity = {
            userId: req.user.id,
            action: `${req.method} ${req.originalUrl}`,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date()
        };

        //log sensitive operations
        const sensitiveRoutes = ['/change-password', '/delete-account', '/admin'];
        if (sensitiveRoutes.some(route => req.originalUrl.includes(route))) {
            console.log('Sensitive operation:', activity);
        }
    }
    next();
};

const authenticateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({
            success: false,
            message: 'API key required'
        });
    }

    //verify apikey (implement api key validation logic)
    //this is a placeholder - replace with actual api key validation
    if (apiKey !== process.env.API_KEY) {
        return res.status(401).json({
            success: false,
            message: 'Invalid API key'
        });
    }

    //set a system user for api requests
    req.user = {
        id: 'system',
        email: 'system@api',
        role: 'api',
        permissions: ['api_access'],
        isEmailVerified: true,
        accountStatus: 'active'
    };

    next();
};


const hybridAuthenticate = (req, res, next) => {
    //try cookie authentication first
    if (req.cookies.accessToken) {
        return authenticate(req, res, next);
    }

    //fall back to api key authentication
    if (req.headers['x-api-key']) {
        return authenticateApiKey(req, res, next);
    }

    return res.status(401).json({
        success: false,
        message: 'Authentication required (cookie or API key)'
    });
};

module.exports = {
    authenticate,
    optionalAuthenticate,
    requireRole,
    requireAnyRole,
    requirePermission,
    requireEmailVerification,
    requireOwnershipOrAdmin,
    checkUserRateLimit,
    logUserActivity,
    authenticateApiKey,
    hybridAuthenticate
};