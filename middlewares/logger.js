const fs = require('fs');
const path = require('path');

const logger = (req, res, next) => {
  const log = `${new Date().toISOString()} - ${req.method} ${req.url}\n`;
  const logPath = path.join(__dirname, '../../logs/requests.log');
  
  fs.appendFile(logPath, log, (err) => {
    if (err) console.error('Error writing to log file:', err);
  });
  
  console.log(`${req.method} ${req.protocol}://${req.get('host')}${req.originalUrl}`);
  next();
};

module.exports = logger;