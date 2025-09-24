const setupGracefulShutdown = () => {
    //graceful shutdown handling
    process.on('SIGTERM', () => {
        console.log('SIGTERM received. Shutting down gracefully...');
        process.exit(0);
    });

    process.on('SIGINT', () => {
        console.log('SIGINT received. Shutting down gracefully...');
        process.exit(0);
    });
};

const setupProcessHandlers = () => {
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
};

module.exports = { setupGracefulShutdown, setupProcessHandlers };