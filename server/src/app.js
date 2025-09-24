const express = require('express');
require('dotenv').config();

const { connectDB } = require('./config/database');
const { testEmailConfig } = require('./helpers/emailHelpers');
const { setupMiddleware } = require('./middlewares');
const { setupRoutes } = require('./routes');
const { setupErrorHandling } = require('./middlewares/errorHandlers.middleware');
const { setupGracefulShutdown, setupProcessHandlers } = require('./utils/processHandlers');

const app = express();

//initialize database connection
connectDB();

//test email configuration on startup (optional)
testEmailConfig().then(isValid => {
    if (isValid) {
        console.log('Email service is configured and ready');
    } else {
        console.warn('Email service configuration may have issues');
    }
}).catch(err => {
    console.log('Email service not configured (skipping test)');
});

//trust proxy for accurate ip addresses behind reverse proxies
app.set('trust proxy', 1);

//setup all middleware
setupMiddleware(app);

//setup all routes
setupRoutes(app);

//setup error handling
setupErrorHandling(app);

//setup graceful shutdown and process handlers
setupGracefulShutdown();
setupProcessHandlers();

module.exports = app;