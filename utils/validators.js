const validator = require('validator');
const User = require('../models/User');

exports.validateRegisterInput = async (data) => {
  const errors = {};

  // Username validation
  if (!data.username || data.username.trim() === '') {
    errors.username = 'Username is required';
  } else if (data.username.length < 3 || data.username.length > 20) {
    errors.username = 'Username must be between 3 and 20 characters';
  } else {
    const user = await User.findOne({ username: data.username });
    if (user) errors.username = 'Username is already taken';
  }

  // Email validation
  if (!data.email || data.email.trim() === '') {
    errors.email = 'Email is required';
  } else if (!validator.isEmail(data.email)) {
    errors.email = 'Email is invalid';
  } else {
    const user = await User.findOne({ email: data.email });
    if (user) errors.email = 'Email is already in use';
  }

  // Password validation
  if (!data.password || data.password.trim() === '') {
    errors.password = 'Password is required';
  } else if (data.password.length < 6) {
    errors.password = 'Password must be at least 6 characters';
  }

  // Password confirmation
  if (data.password !== data.passwordConfirm) {
    errors.passwordConfirm = 'Passwords do not match';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0
  };
};

exports.validateLoginInput = (data) => {
  const errors = {};

  if (!data.email || data.email.trim() === '') {
    errors.email = 'Email is required';
  } else if (!validator.isEmail(data.email)) {
    errors.email = 'Email is invalid';
  }

  if (!data.password || data.password.trim() === '') {
    errors.password = 'Password is required';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0
  };
};

exports.validateMessageInput = (data) => {
  const errors = {};

  if (!data.conversationId && !data.recipientId) {
    errors.recipient = 'Either conversationId or recipientId is required';
  }

  if (!data.text && (!data.media || data.media.length === 0)) {
    errors.content = 'Either text or media is required';
  }

  return {
    errors,
    isValid: Object.keys(errors).length === 0
  };
};