const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const compression = require('compression');
require('dotenv').config();

const { connectDB } = require('./config/database');
const routes = require('./routes');

const { securityHeaders } = require('./helpers/securityHelpers');
const { testEmailConfig } = require('./helpers/emailHelpers');

const app = express();

//connect to mongoDB
connectDB();

//test email configuration on startup (optional - remove if you don't use email)
testEmailConfig().then(isValid => {
    if (isValid) {
        console.log('✅ Email service is configured and ready');
    } else {
        console.warn('⚠️  Email service configuration may have issues');
    }
}).catch(err => {
    console.log('📧 Email service not configured (skipping test)');
});

//trust proxy (for accurate IP addresses behind reverse proxies)
app.set('trust proxy', 1);

//security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

//cors configuration
app.use(cors({
    origin: function (origin, callback) {
        //allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            process.env.FRONTEND_URL || 'http://localhost:5173',
            'http://localhost:5173',
            'http://localhost:8000',
            'http://127.0.0.1:5173'
        ];
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, //allow cookies
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie']
}));

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

//apply custom security headers
app.use(securityHeaders);

//logging middleware
if (process.env.NODE_ENV === 'production') {
    app.use(morgan('combined'));
} else {
    app.use(morgan('dev'));
}

//request logging for debugging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
    next();
});

//health check endpoint
app.get('/health', (req, res) => {
    res.json({
        success: true,
        message: 'API is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

//api routes
app.use('/api', routes);

//api documentation route (basic info)
app.get('/api-docs', (req, res) => {
    res.json({
        success: true,
        message: 'API v1.0',
        documentation: {
            message: 'API routes are defined in your routes/index.js file',
            health: 'GET /health',
            apiDocs: 'GET /api-docs'
        }
    });
});

//handle undefined routes
// app.use('*', (req, res) => {
//     res.status(404).json({
//         success: false,
//         message: `Route ${req.originalUrl} not found`,
//         availableRoutes: {
//             api: '/api',
//             health: '/health',
//             documentation: '/api-docs'
//         }
//     });
// });

//global error handler
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);

    //mongoose validation error
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: 'Validation Error',
            errors: Object.values(err.errors).map(e => e.message)
        });
    }

    //mongoose cast error (invalid ObjectId)
    if (err.name === 'CastError') {
        return res.status(400).json({
            success: false,
            message: 'Invalid ID format'
        });
    }

    //jwt errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }

    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            success: false,
            message: 'Token expired'
        });
    }

    //cors error
    if (err.message.includes('CORS')) {
        return res.status(403).json({
            success: false,
            message: 'CORS policy violation'
        });
    }

    //default error
    res.status(err.status || 500).json({
        success: false,
        message: process.env.NODE_ENV === 'production' 
            ? 'Internal server error' 
            : err.message,
        ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
    });
});

//graceful shutdown handling
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received. Shutting down gracefully...');
    process.exit(0);
});

//handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Promise Rejection:', err);
    process.exit(1);
});

//handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

module.exports = app;