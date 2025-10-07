const services = require('../services');

class UserController {
    constructor() {
        this.userService = services.getUserService();
    }
    
    async getProfile(req, res) {
        try {
            const userId = req.user.id;
            const result = await this.userService.getProfile(userId);

            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Get profile error:', error);
            
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

    async updateProfile(req, res) {
        try {
            const userId = req.user.id;
            const result = await this.userService.updateProfile(userId, req.body);

            res.json({
                success: true,
                message: 'Profile updated successfully',
                data: result
            });
        } catch (error) {
            console.error('Update profile error:', error);
            
            if (error.message.includes('Validation failed')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('No valid fields')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('not found')) {
                return res.status(404).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.name === 'ValidationError') {
                return res.status(400).json({
                    success: false,
                    message: 'Validation error',
                    errors: Object.values(error.errors).map(err, err.message)
                });
            }

            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    };

    async changePassword(req, res) {
        try {
            const userId = req.user.id;
            const { currentPassword, newPassword } = req.body;
            
            const result = await this.userService.changePassword(userId, currentPassword, newPassword);

            res.json({
                success: true,
                message: result.message
            });
        } catch (error) {
            console.error('Change password error:', error);
            
            if (error.message.includes('required') || 
                error.message.includes('incorrect') ||
                error.message.includes('validation') ||
                error.message.includes('stronger password') ||
                error.message.includes('different from current')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
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

    async getStats(req, res) {
        try {
            const userId = req.user.id;
            const result = await this.userService.getUserStats(userId);

            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Get stats error:', error);
            
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

    async getLoginHistory(req, res) {
        try {
            const userId = req.user.id;
            const { limit, page } = req.query;
            
            const result = await this.userService.getLoginHistory(userId, page, limit);

            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Get login history error:', error);
            
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

    async deleteAccount(req, res) {
        try {
            const userId = req.user.id;
            const { password, confirmation } = req.body;
            
            const result = await this.userService.deleteAccount(userId, password, confirmation);

            res.json({
                success: true,
                message: result.message
            });
        } catch (error) {
            console.error('Delete account error:', error);
            
            if (error.message.includes('required') || 
                error.message.includes('incorrect')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
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

    async getAllUsers(req, res) {
        try {
            const result = await this.userService.getAllUsers(req.user, req.query);

            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Get all users error:', error);
            
            if (error.message.includes('Access denied')) {
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

    async getUserById(req, res) {
        try {
            const { userId } = req.params;
            const result = await this.userService.getUserById(req.user, userId);

            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Get user by ID error:', error);
            
            if (error.message.includes('Access denied')) {
                return res.status(403).json({
                    success: false,
                    message: error.message
                });
            }
            
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

    async updateUserRole(req, res) {
        try {
            const { userId } = req.params;
            const { role, permissions } = req.body;
            
            const result = await this.userService.updateUserRole(req.user, userId, role, permissions);

            res.json({
                success: true,
                message: 'User role updated successfully',
                data: result
            });
        } catch (error) {
            console.error('Update user role error:', error);
            
            if (error.message.includes('Access denied') || 
                error.message.includes('Insufficient permissions')) {
                return res.status(403).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('Invalid role') ||
                error.message.includes('Only superadmin') ||
                error.message.includes('Cannot change your own')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
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


    async updateAccountStatus(req, res) {
        try {
            const { userId } = req.params;
            const { accountStatus, isActive } = req.body;
            
            const result = await this.userService.updateAccountStatus(req.user, userId, accountStatus, isActive);

            res.json({
                success: true,
                message: 'Account status updated successfully',
                data: result
            });
        } catch (error) {
            console.error('Update account status error:', error);
            
            if (error.message.includes('Access denied')) {
                return res.status(403).json({
                    success: false,
                    message: error.message
                });
            }
            
            if (error.message.includes('Invalid account status') ||
                error.message.includes('Cannot suspend your own')) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }
            
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

module.exports = new UserController();