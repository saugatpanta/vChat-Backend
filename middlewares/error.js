const logger = require('./logger');

// Error handler middleware
exports.errorHandler = (err, req, res, next) => {
  // Log the error
  logger.error(`Error Handler: ${err.message}`);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Resource not found',
    });
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json({
      success: false,
      message: `Duplicate field value entered for ${field}`,
    });
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return res.status(400).json({
      success: false,
      message: messages.join(', '),
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Not authorized',
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Session expired, please login again',
    });
  }

  // Default to 500 server error
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Server Error',
  });
};