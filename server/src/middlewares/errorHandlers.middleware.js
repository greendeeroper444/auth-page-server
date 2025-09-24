const setupErrorHandling = (app) => {
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

        //mongoose cast error (invalid object id)
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
};

module.exports = { setupErrorHandling };