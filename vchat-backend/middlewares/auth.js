const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('./logger');
const { JWT_SECRET } = require('../utils/constants');

// Protect routes
exports.protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    logger.warn('Attempt to access protected route without token');
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route',
    });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = await User.findById(decoded.id);

    if (!req.user) {
      logger.warn('Token valid but user not found');
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route',
      });
    }

    next();
  } catch (error) {
    logger.error(`Auth Middleware Error: ${error.message}`);
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route',
    });
  }
};

// Grant access to specific roles
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      logger.warn(
        `User ${req.user.id} attempted to access admin route without authorization`
      );
      return res.status(403).json({
        success: false,
        message: `User role ${req.user.role} is not authorized to access this route`,
      });
    }
    next();
  };
};

// Check if user is verified
exports.checkVerified = async (req, res, next) => {
  if (!req.user.verified) {
    return res.status(403).json({
      success: false,
      message: 'Please verify your email first',
    });
  }
  next();
};