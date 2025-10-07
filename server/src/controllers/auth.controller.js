const services = require('../services');
const { getRefreshTokenConfig, getAccessTokenConfig, getCookieConfig } = require('../helpers/cookie.helper');

class AuthController {
    constructor() {
        this.authService = services.getAuthService();
    }

    async register(req, res) {
        try {
            const result = await this.authService.register(req.body, req);
            
            res.status(201).json({
                success: true,
                message: 'User registered successfully. Please check your email to verify your account.',
                data: result
            });
        } catch (error) {
            console.error('Registration error:', error);
            
            if (error.message.includes('already exists')) {
                return res.status(409).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('Validation failed')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('stronger password')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error during registration'
            });
        }
    };

    async login(req, res) {
        try {
            const result = await this.authService.login(req.body, req);
            const isProduction = process.env.NODE_ENV === 'production';
            const { user, tokens, rememberMe } = result;

            const accessTokenCookie = getAccessTokenConfig(isProduction);
            const refreshTokenCookie = rememberMe ? 
                getRefreshTokenConfig(isProduction) : 
                {
                    ...getCookieConfig(isProduction),
                    maxAge: 24 * 60 * 60 * 1000 // 24 hours
                };

            res.cookie('accessToken', tokens.accessToken, accessTokenCookie);
            res.cookie('refreshToken', tokens.refreshToken, refreshTokenCookie);

            res.json({
                success: true,
                message: 'Login successful',
                data: { user }
            });
        } catch (error) {
            console.error('Login error:', error);
            
            if (error.message.includes('Invalid credentials')) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }
            
            if (error.message.includes('locked')) {
                return res.status(423).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('not active')) {
                return res.status(403).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('Validation failed')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error during login'
            });
        }
    }

    async refreshToken(req, res) {
        try {
            const refreshToken = req.cookies.refreshToken;
            const result = await this.authService.refreshToken(refreshToken);
            const isProduction = process.env.NODE_ENV === 'production';
            const { tokens } = result;

            //update cookies
            res.cookie('accessToken', tokens.accessToken, getAccessTokenConfig(isProduction));
            res.cookie('refreshToken', tokens.refreshToken, getRefreshTokenConfig(isProduction));

            res.json({
                success: true,
                message: 'Token refreshed successfully'
            });
        } catch (error) {
            console.error('Refresh token error:', error);
            
            if (error.message.includes('required') || error.message.includes('Invalid')) {
                //clear cookies on invalid token
                res.clearCookie('accessToken');
                res.clearCookie('refreshToken');
                
                return res.status(401).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('not active')) {
                //clear cookies on inactive account
                res.clearCookie('accessToken');
                res.clearCookie('refreshToken');
                
                return res.status(403).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    };


    async logout(req, res) {
        try {
            const refreshToken = req.cookies.refreshToken;
            await this.authService.logout(refreshToken);

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

    async logoutAll(req, res) {
        try {
            const userId = req.user.id;
            await this.authService.logoutAll(userId);

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

    async verifyEmailAddress(req, res) {
        try {
            const { token } = req.query;
            const result = await this.authService.verifyEmail(token);

            res.json({
                success: true,
                message: 'Email verified successfully',
                data: result
            });
        } catch (error) {
            console.error('Email verification error:', error);
            
            if (error.message.includes('required') || error.message.includes('Invalid') || error.message.includes('expired')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error during email verification'
            });
        }
    };

    async resendEmailVerification(req, res) {
        try {
            const { email } = req.body;
            const result = await this.authService.resendEmailVerification(email);

            res.json({
                success: true,
                message: result.message,
                data: result.emailSent ? { emailSent: result.emailSent } : undefined
            });
        } catch (error) {
            console.error('Resend verification error:', error);
            
            if (error.message.includes('required')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('already verified')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    };


    async requestPasswordReset(req, res) {
        try {
            const { email } = req.body;
            const result = await this.authService.requestPasswordReset(email);

            res.json({
                success: true,
                message: result.message,
                data: result.emailSent ? { emailSent: result.emailSent } : undefined
            });
        } catch (error) {
            console.error('Password reset request error:', error);
            
            if (error.message.includes('required')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    };


    async resetPassword(req, res) {
        try {
            const { token, password } = req.body;
            const result = await this.authService.resetPassword(token, password);

            res.json({
                success: true,
                message: result.message
            });
        } catch (error) {
            console.error('Password reset error:', error);
            
            if (error.message.includes('required') || 
                error.message.includes('validation') || 
                error.message.includes('stronger password')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('Invalid') || error.message.includes('expired')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error during password reset'
            });
        }
    }

    async getUserProfile(req, res) {
        try {
            const userId = req.user.id;
            const result = await this.authService.getUserProfile(userId);

            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Get user profile error:', error);
            
            if (error.message.includes('not found')) {
                return res.status(404).json({
                    success: false,
                    message: error.message
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    };
}

module.exports = new AuthController();