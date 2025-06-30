const colors = require('colors');

const logger = (req, res, next) => {
  console.log(
    `${req.method} ${req.protocol}://${req.get('host')}${req.originalUrl}`.blue
  );
  next();
};

module.exports = logger;