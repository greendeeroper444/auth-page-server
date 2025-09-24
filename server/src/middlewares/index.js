const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const compression = require('compression');

const { securityHeaders } = require('../helpers/security.helper');
const { corsConfig } = require('../config/cors');
const { helmetConfig } = require('../config/security');
const { requestLogger } = require('./requestLogger.middleware');

const setupMiddleware = (app) => {
    //security middleware
    app.use(helmet(helmetConfig));

    //cors configuration
    app.use(cors(corsConfig));

    //body parsing middleware
    app.use(express.json({ 
        limit: '10mb',
        verify: (req, res, buf) => {
            try {
                JSON.parse(buf);
            } catch (e) {
                res.status(400).json({ 
                    success: false, 
                    message: 'Invalid JSON format' 
                });
                throw new Error('Invalid JSON');
            }
        }
    }));

    app.use(express.urlencoded({ 
        extended: true, 
        limit: '10mb' 
    }));

    //cookie parsing
    app.use(cookieParser());

    //compression middleware
    app.use(compression());

    //custom security headers
    app.use(securityHeaders);

    // logging middleware
    if (process.env.NODE_ENV === 'production') {
        app.use(morgan('combined'));
    } else {
        app.use(morgan('dev'));
    }

    //request logging for debugging
    app.use(requestLogger);
};

module.exports = { setupMiddleware };