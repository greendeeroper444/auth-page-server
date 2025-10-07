const repositories = require('../repositories');
const AuthService = require('./auth.service');
const UserService = require('./user.service');

class ServiceContainer {
    constructor() {
        this._authService = null;
        this._userService = null;
    }

    getAuthService() {
        if (!this._authService) {
            this._authService = new AuthService(
                repositories.getAuthRepository()
            );
        }
        return this._authService;
    }

    getUserService() {
        if (!this._userService) {
            this._userService = new UserService(
                repositories.getUserRepository()
            );
        }
        return this._userService;
    }

    reset() {
        this._authService = null;
        this._userService = null;
    }
}

module.exports = new ServiceContainer();