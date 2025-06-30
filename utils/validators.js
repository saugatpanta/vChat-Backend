const validator = require('validator');
const { ErrorResponse } = require('./ErrorResponse');

exports.validateRegisterInput = (data) => {
  const errors = {};

  // Name validation
  if (validator.isEmpty(data.name)) {
    errors.name = 'Name field is required';
  } else if (!validator.isLength(data.name, { min: 2, max: 50 })) {
    errors.name = 'Name must be between 2 and 50 characters';
  }

  // Email validation
  if (validator.isEmpty(data.email)) {
    errors.email = 'Email field is required';
  } else if (!validator.isEmail(data.email)) {
    errors.email = 'Email is invalid';
  }

  // Username validation
  if (validator.isEmpty(data.username)) {
    errors.username = 'Username field is required';
  } else if (!validator.isLength(data.username, { min: 3, max: 30 })) {
    errors.username = 'Username must be between 3 and 30 characters';
  } else if (!/^[a-zA-Z0-9_]+$/.test(data.username)) {
    errors.username = 'Username can only contain letters, numbers and underscores';
  }

  // Password validation
  if (validator.isEmpty(data.password)) {
    errors.password = 'Password field is required';
  } else if (!validator.isLength(data.password, { min: 6 })) {
    errors.password = 'Password must be at least 6 characters';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0
  };
};

exports.validateLoginInput = (data) => {
  const errors = {};

  // Email validation
  if (validator.isEmpty(data.email)) {
    errors.email = 'Email field is required';
  } else if (!validator.isEmail(data.email)) {
    errors.email = 'Email is invalid';
  }

  // Password validation
  if (validator.isEmpty(data.password)) {
    errors.password = 'Password field is required';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0
  };
};

exports.validateUpdateProfileInput = (data) => {
  const errors = {};

  // Name validation
  if (data.name && !validator.isLength(data.name, { min: 2, max: 50 })) {
    errors.name = 'Name must be between 2 and 50 characters';
  }

  // Username validation
  if (data.username && !validator.isLength(data.username, { min: 3, max: 30 })) {
    errors.username = 'Username must be between 3 and 30 characters';
  } else if (data.username && !/^[a-zA-Z0-9_]+$/.test(data.username)) {
    errors.username = 'Username can only contain letters, numbers and underscores';
  }

  // Bio validation
  if (data.bio && !validator.isLength(data.bio, { max: 150 })) {
    errors.bio = 'Bio cannot be more than 150 characters';
  }

  // Website validation
  if (data.website && !validator.isURL(data.website)) {
    errors.website = 'Website URL is invalid';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0
  };
};

exports.validatePasswordInput = (data) => {
  const errors = {};

  // Current password validation
  if (validator.isEmpty(data.currentPassword)) {
    errors.currentPassword = 'Current password is required';
  }

  // New password validation
  if (validator.isEmpty(data.newPassword)) {
    errors.newPassword = 'New password is required';
  } else if (!validator.isLength(data.newPassword, { min: 6 })) {
    errors.newPassword = 'Password must be at least 6 characters';
  }

  // Confirm password validation
  if (validator.isEmpty(data.confirmPassword)) {
    errors.confirmPassword = 'Please confirm your password';
  } else if (!validator.equals(data.newPassword, data.confirmPassword)) {
    errors.confirmPassword = 'Passwords do not match';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0
  };
};