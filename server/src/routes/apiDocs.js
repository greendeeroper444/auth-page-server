const apiDocs = (req, res) => {
    res.json({
        success: true,
        message: 'API v1.0',
        documentation: {
            message: 'API routes are defined in your routes/index.js file',
            health: 'GET /health',
            apiDocs: 'GET /api-docs'
        }
    });
};

module.exports = { apiDocs };