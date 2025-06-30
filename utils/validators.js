const validator = require('validator');
const { StatusCodes } = require('http-status-codes');

const validateRegisterInput = (data) => {
  const errors = {};

  // Validate username
  if (!data.username || data.username.trim() === '') {
    errors.username = 'Username is required';
  } else if (data.username.length < 3 || data.username.length > 20) {
    errors.username = 'Username must be between 3 and 20 characters';
  }

  // Validate email
  if (!data.email || data.email.trim() === '') {
    errors.email = 'Email is required';
  } else if (!validator.isEmail(data.email)) {
    errors.email = 'Email is invalid';
  }

  // Validate password
  if (!data.password || data.password.trim() === '') {
    errors.password = 'Password is required';
  } else if (data.password.length < 6) {
    errors.password = 'Password must be at least 6 characters';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0,
  };
};

const validateLoginInput = (data) => {
  const errors = {};

  // Validate email
  if (!data.email || data.email.trim() === '') {
    errors.email = 'Email is required';
  } else if (!validator.isEmail(data.email)) {
    errors.email = 'Email is invalid';
  }

  // Validate password
  if (!data.password || data.password.trim() === '') {
    errors.password = 'Password is required';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0,
  };
};

const validateStoryInput = (data) => {
  const errors = {};

  // Validate caption
  if (data.caption && data.caption.length > 100) {
    errors.caption = 'Caption must be less than 100 characters';
  }

  // Validate location
  if (data.location && data.location.length > 50) {
    errors.location = 'Location must be less than 50 characters';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0,
  };
};

module.exports = {
  validateRegisterInput,
  validateLoginInput,
  validateStoryInput,
};