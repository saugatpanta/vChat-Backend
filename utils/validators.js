const validator = require('validator');
const { User } = require('../models');

// Validate registration data
const validateRegisterInput = async (data) => {
  const errors = {};

  // Username validation
  if (!data.username || !validator.isLength(data.username, { min: 3, max: 20 })) {
    errors.username = 'Username must be between 3 and 20 characters';
  } else {
    const existingUser = await User.findOne({ username: data.username });
    if (existingUser) {
      errors.username = 'Username is already taken';
    }
  }

  // Email validation
  if (!data.email || !validator.isEmail(data.email)) {
    errors.email = 'Please provide a valid email';
  } else {
    const existingUser = await User.findOne({ email: data.email });
    if (existingUser) {
      errors.email = 'Email is already registered';
    }
  }

  // Password validation
  if (!data.password || !validator.isLength(data.password, { min: 6 })) {
    errors.password = 'Password must be at least 6 characters';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0,
  };
};

// Validate login data
const validateLoginInput = (data) => {
  const errors = {};

  if (!data.email || !validator.isEmail(data.email)) {
    errors.email = 'Please provide a valid email';
  }

  if (!data.password) {
    errors.password = 'Password is required';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0,
  };
};

// Validate password reset data
const validatePasswordResetInput = (data) => {
  const errors = {};

  if (!data.password || !validator.isLength(data.password, { min: 6 })) {
    errors.password = 'Password must be at least 6 characters';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0,
  };
};

module.exports = {
  validateRegisterInput,
  validateLoginInput,
  validatePasswordResetInput,
};