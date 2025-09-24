const main = require('./main');
const { healthCheck } = require('./health');
const { apiDocs } = require('./apiDocs');

const setupRoutes = (app) => {
    //health check endpoint
    app.get('/health', healthCheck);

    //api documentation route
    app.get('/api-docs', apiDocs);

    //main routes
    app.use('/api', main);
};

module.exports = { setupRoutes };