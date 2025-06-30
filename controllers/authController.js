const User = require('../models/User');
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const { StatusCodes } = require('http-status-codes');
const validator = require('validator');
const logger = require('../middlewares/logger');
const sendEmail = require('../services/emailService');

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
const register = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  // Validation
  if (!username || !email || !password) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide all required fields');
  }

  if (!validator.isEmail(email)) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide a valid email');
  }

  if (password.length < 6) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Password must be at least 6 characters');
  }

  // Check if user exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('User already exists');
  }

  const usernameExists = await User.findOne({ username });
  if (usernameExists) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Username is already taken');
  }

  // Create user
  const user = await User.create({
    username,
    email,
    password,
  });

  if (user) {
    // Generate token
    const token = user.generateAuthToken();

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    logger.info(`New user registered: ${user.email}`);

    res.status(StatusCodes.CREATED).json({
      _id: user._id,
      username: user.username,
      email: user.email,
      profilePicture: user.profilePicture,
      token,
    });
  } else {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Invalid user data');
  }
});

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide email and password');
  }

  // Check for user
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    res.status(StatusCodes.UNAUTHORIZED);
    throw new Error('Invalid credentials');
  }

  // Check if password matches
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    res.status(StatusCodes.UNAUTHORIZED);
    throw new Error('Invalid credentials');
  }

  // Generate token
  const token = user.generateAuthToken();

  // Set cookie
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  logger.info(`User logged in: ${user.email}`);

  res.status(StatusCodes.OK).json({
    _id: user._id,
    username: user.username,
    email: user.email,
    profilePicture: user.profilePicture,
    token,
  });
});

// @desc    Logout user / clear cookie
// @route   POST /api/auth/logout
// @access  Private
const logout = asyncHandler(async (req, res) => {
  res.cookie('token', '', {
    httpOnly: true,
    expires: new Date(0),
  });

  logger.info(`User logged out: ${req.user.email}`);

  res.status(StatusCodes.OK).json({ message: 'Logged out successfully' });
});

// @desc    Get user profile
// @route   GET /api/auth/profile
// @access  Private
const getProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select('-password');

  if (!user) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('User not found');
  }

  res.status(StatusCodes.OK).json(user);
});

// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
const updateProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('User not found');
  }

  const { username, bio } = req.body;

  if (username) {
    const usernameExists = await User.findOne({ username });
    if (usernameExists && usernameExists._id.toString() !== user._id.toString()) {
      res.status(StatusCodes.BAD_REQUEST);
      throw new Error('Username is already taken');
    }
    user.username = username;
  }

  if (bio) {
    user.bio = bio;
  }

  const updatedUser = await user.save();

  res.status(StatusCodes.OK).json({
    _id: updatedUser._id,
    username: updatedUser.username,
    email: updatedUser.email,
    profilePicture: updatedUser.profilePicture,
    bio: updatedUser.bio,
  });
});

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide email');
  }

  const user = await User.findOne({ email });

  if (!user) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('User not found');
  }

  // Generate reset token
  const resetToken = jwt.sign(
    { id: user._id },
    process.env.JWT_RESET_SECRET,
    { expiresIn: '10m' }
  );

  // Create reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

  // Send email
  const message = `
    <h2>Hello ${user.username}</h2>
    <p>Please use the link below to reset your password</p>
    <p>This reset link is valid for only 10 minutes</p>
    <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
    <p>Regards,</p>
    <p>vChat Team</p>
  `;

  try {
    await sendEmail({
      to: user.email,
      subject: 'Password Reset Request',
      html: message,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      message: 'Password reset email sent',
    });
  } catch (error) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    res.status(StatusCodes.INTERNAL_SERVER_ERROR);
    throw new Error('Email could not be sent');
  }
});

// @desc    Reset password
// @route   PUT /api/auth/reset-password/:resetToken
// @access  Public
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  if (!password) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide a password');
  }

  try {
    // Verify token
    const decoded = jwt.verify(resetToken, process.env.JWT_RESET_SECRET);

    // Get user
    const user = await User.findById(decoded.id);

    if (!user) {
      res.status(StatusCodes.NOT_FOUND);
      throw new Error('User not found');
    }

    // Set new password
    user.password = password;
    await user.save();

    res.status(StatusCodes.OK).json({
      success: true,
      message: 'Password updated successfully',
    });
  } catch (error) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Invalid or expired token');
  }
});

module.exports = {
  register,
  login,
  logout,
  getProfile,
  updateProfile,
  forgotPassword,
  resetPassword,
};