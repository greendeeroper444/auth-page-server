const dotenv = require('dotenv');

dotenv.config();

const config = {
    //application settings
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: parseInt(process.env.PORT) || 8000,
    
    //jwt configuration
    JWT_SECRET: process.env.JWT_SECRET || 'default-secret',
    
    //mongoDB configuration
    DB_NAME: 'auth_secure',
    MONGODB_URI: process.env.MONGODB_URI || `mongodb://127.0.0.1:27017/auth_secure`
};

//validation checks
if (!config.JWT_SECRET || config.JWT_SECRET === 'default-secret') {
    console.error('JWT_SECRET is required and should not use default value');
    process.exit(1);
}

//for production, ensure MONGODB_URI is explicitly set
if (config.NODE_ENV === 'production' && !process.env.MONGODB_URI) {
    console.error('MONGODB_URI is required in production environment');
    process.exit(1);
}

module.exports = config;