const validator = require('validator');
const User = require('../models/User');

// Validate register input
exports.validateRegisterInput = async (req, res, next) => {
  const { username, email, password, confirmPassword } = req.body;

  // Check if all fields are filled
  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({
      success: false,
      error: 'Please fill in all fields'
    });
  }

  // Check if username is valid
  if (!validator.isLength(username, { min: 3, max: 20 })) {
    return res.status(400).json({
      success: false,
      error: 'Username must be between 3 and 20 characters'
    });
  }

  // Check if email is valid
  if (!validator.isEmail(email)) {
    return res.status(400).json({
      success: false,
      error: 'Please provide a valid email'
    });
  }

  // Check if password is valid
  if (!validator.isLength(password, { min: 6, max: 30 })) {
    return res.status(400).json({
      success: false,
      error: 'Password must be between 6 and 30 characters'
    });
  }

  // Check if passwords match
  if (password !== confirmPassword) {
    return res.status(400).json({
      success: false,
      error: 'Passwords do not match'
    });
  }

  // Check if username or email already exists
  const user = await User.findOne({ $or: [{ username }, { email }] });
  if (user) {
    return res.status(400).json({
      success: false,
      error: 'Username or email already exists'
    });
  }

  next();
};

// Validate login input
exports.validateLoginInput = (req, res, next) => {
  const { email, password } = req.body;

  // Check if all fields are filled
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Please fill in all fields'
    });
  }

  next();
};