const AuthRepository = require('./auth.repository');
const UserRepository = require('./user.repository');

class RepositoryContainer {
    constructor() {
        this._authRepository = null;
        this._userRepository = null;
    }

    getAuthRepository() {
        if (!this._authRepository) {
            this._authRepository = new AuthRepository();
        }
        return this._authRepository;
    }

    getUserRepository() {
        if (!this._userRepository) {
            this._userRepository = new UserRepository();
        }
        return this._userRepository;
    }

    reset() {
        this._authRepository = null;
        this._userRepository = null;
    }
}

module.exports = new RepositoryContainer();