/**
 * get base cookie configuration
 * @param {Boolean} isProduction - whether running in production
 * @returns {Object} cookie configuration
 */
const getCookieConfig = (isProduction = false) => ({
    httpOnly: true,
    secure: isProduction, //only secure in production (HTTPS)
    sameSite: isProduction ? 'strict' : 'lax', //more restrictive in production
    path: '/',
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined
});

/**
 * get access token cookie configuration
 * @param {Boolean} isProduction - whether running in production
 * @returns {Object} access token cookie configuration
 */
const getAccessTokenConfig = (isProduction = false) => ({
    ...getCookieConfig(isProduction),
    maxAge: 15 * 60 * 1000 //15 minutes
});

/**
 * get refresh token cookie configuration
 * @param {Boolean} isProduction - whether running in production
 * @param {Boolean} rememberMe - whether user chose "remember me"
 * @returns {Object} refresh token cookie configuration
 */
const getRefreshTokenConfig = (isProduction = false, rememberMe = false) => ({
    ...getCookieConfig(isProduction),
    maxAge: rememberMe ? 
        7 * 24 * 60 * 60 * 1000 : //7 days if remember me
        24 * 60 * 60 * 1000      //24 hours if not
});

/**
 * set authentication cookies on response
 * @param {Object} res - express response object
 * @param {Object} tokens - object containing accessToken and refreshToken
 * @param {Object} options - options object
 * @param {Boolean} options.rememberMe - whether user chose remember me
 * @param {Boolean} options.isProduction - whether running in production
 */
const setAuthCookies = (res, tokens, { rememberMe = false, isProduction = false } = {}) => {
    const accessTokenConfig = getAccessTokenConfig(isProduction);
    const refreshTokenConfig = getRefreshTokenConfig(isProduction, rememberMe);

    res.cookie('accessToken', tokens.accessToken, accessTokenConfig);
    res.cookie('refreshToken', tokens.refreshToken, refreshTokenConfig);
    
    //debug logging in development
    if (!isProduction) {
        console.log('Setting auth cookies:', {
            accessTokenExpiry: new Date(Date.now() + accessTokenConfig.maxAge),
            refreshTokenExpiry: new Date(Date.now() + refreshTokenConfig.maxAge),
            rememberMe
        });
    }
};

/**
 * clear authentication cookies from response
 * @param {Object} res - express response object
 * @param {Boolean} isProduction - whether running in production
 */
const clearAuthCookies = (res, isProduction = false) => {
    const cookieConfig = {
        ...getCookieConfig(isProduction),
        maxAge: 0 //expire immediately
    };
    
    res.clearCookie('accessToken', cookieConfig);
    res.clearCookie('refreshToken', cookieConfig);
    
    //debug logging in development
    if (!isProduction) {
        console.log('Clearing auth cookies');
    }
};

/**
 * extract tokens from request (cookies first, then headers for fallback)
 * @param {Object} req - express request object
 * @returns {Object} object containing accessToken and refreshToken
 */
const extractTokens = (req) => {
    let accessToken = req.cookies?.accessToken;
    let refreshToken = req.cookies?.refreshToken;
    
    //fallback to Authorization header if no access token cookie
    if (!accessToken) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            accessToken = authHeader.substring(7);
        }
    }
    
    //fallback to request body for refresh token (for API compatibility)
    if (!refreshToken && req.body?.refreshToken) {
        refreshToken = req.body.refreshToken;
    }
    
    return { 
        accessToken, 
        refreshToken,
        source: {
            accessToken: req.cookies?.accessToken ? 'cookie' : 'header',
            refreshToken: req.cookies?.refreshToken ? 'cookie' : 'body'
        }
    };
};

/**
 * check if request has valid cookie format
 * @param {Object} req - wxpress request object
 * @returns {Boolean} whether request has proper cookie setup
 */
const hasCookieSupport = (req) => {
    return req.cookies && typeof req.cookies === 'object';
};

/**
 * get cookie expiry time
 * @param {String} cookieType - 'access' or 'refresh'
 * @param {Boolean} rememberMe - whether remember me is enabled
 * @returns {Date} Expiry date
 */
const getCookieExpiry = (cookieType, rememberMe = false) => {
    const now = Date.now();
    
    if (cookieType === 'access') {
        return new Date(now + (15 * 60 * 1000)); //15 minutes
    } else if (cookieType === 'refresh') {
        const maxAge = rememberMe ? 
            (7 * 24 * 60 * 60 * 1000) : //7 days
            (24 * 60 * 60 * 1000);     //24 hours
        return new Date(now + maxAge);
    }
    
    return new Date(now);
};

module.exports = {
    getCookieConfig,
    getAccessTokenConfig,
    getRefreshTokenConfig,
    setAuthCookies,
    clearAuthCookies,
    extractTokens,
    hasCookieSupport,
    getCookieExpiry
};