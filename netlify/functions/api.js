const serverless = require('serverless-http');
const path = require('path');
const app = require(path.join(__dirname, '..', '..', 'server'));

module.exports.handler = serverless(app);
