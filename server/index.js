const app = require('./src/app');
const config = require('./src/config/environment');

const PORT = config.PORT || 8000;

app.listen(PORT, () => {
    console.log(`
        API Server is running!
        Port: ${PORT}
        Environment: ${process.env.NODE_ENV || 'development'}
        Health Check: http://localhost:${PORT}/health
        API Docs: http://localhost:${PORT}/api-docs
    `);
});