const asyncHandler = require('express-async-handler');
const { StatusCodes } = require('http-status-codes');
const User = require('../models/User');
const { cloudinary } = require('../config/cloudinary');
const logger = require('../middlewares/logger');

// @desc    Get all users (search)
// @route   GET /api/users
// @access  Private
const getUsers = asyncHandler(async (req, res) => {
  const { search } = req.query;
  const userId = req.user._id;

  let query = {
    _id: { $ne: userId },
    status: 'active',
  };

  if (search) {
    query.$or = [
      { username: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } },
    ];
  }

  const users = await User.find(query)
    .select('username profilePicture isOnline lastSeen')
    .limit(20);

  res.status(StatusCodes.OK).json(users);
});

// @desc    Get user profile
// @route   GET /api/users/:userId
// @access  Private
const getUserProfile = asyncHandler(async (req, res) => {
  const { userId } = req.params;

  const user = await User.findById(userId)
    .select('-password -settings -status -role')
    .populate('followers', 'username profilePicture')
    .populate('following', 'username profilePicture');

  if (!user) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('User not found');
  }

  res.status(StatusCodes.OK).json(user);
});

// @desc    Update user profile picture
// @route   PUT /api/users/profile-picture
// @access  Private
const updateProfilePicture = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  if (!req.file) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please upload a file');
  }

  // Upload new picture to Cloudinary
  const result = await cloudinary.uploader.upload(req.file.path, {
    folder: 'vchat/profile-pictures',
    width: 500,
    height: 500,
    crop: 'fill',
  });

  // Delete old picture if it exists
  const user = await User.findById(userId);
  if (user.profilePicture) {
    const publicId = user.profilePicture.split('/').pop().split('.')[0];
    await cloudinary.uploader.destroy(`vchat/profile-pictures/${publicId}`);
  }

  // Update user profile picture
  user.profilePicture = result.secure_url;
  await user.save();

  res.status(StatusCodes.OK).json({
    profilePicture: user.profilePicture,
  });
});

// @desc    Update user cover photo
// @route   PUT /api/users/cover-photo
// @access  Private
const updateCoverPhoto = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  if (!req.file) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please upload a file');
  }

  // Upload new cover photo to Cloudinary
  const result = await cloudinary.uploader.upload(req.file.path, {
    folder: 'vchat/cover-photos',
    width: 1500,
    height: 500,
    crop: 'fill',
  });

  // Delete old cover photo if it exists
  const user = await User.findById(userId);
  if (user.coverPicture) {
    const publicId = user.coverPicture.split('/').pop().split('.')[0];
    await cloudinary.uploader.destroy(`vchat/cover-photos/${publicId}`);
  }

  // Update user cover photo
  user.coverPicture = result.secure_url;
  await user.save();

  res.status(StatusCodes.OK).json({
    coverPicture: user.coverPicture,
  });
});

// @desc    Follow/Unfollow a user
// @route   PUT /api/users/:userId/follow
// @access  Private
const followUser = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const currentUserId = req.user._id;

  if (userId === currentUserId.toString()) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('You cannot follow yourself');
  }

  const userToFollow = await User.findById(userId);
  const currentUser = await User.findById(currentUserId);

  if (!userToFollow || !currentUser) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('User not found');
  }

  const isFollowing = currentUser.following.includes(userId);

  if (isFollowing) {
    // Unfollow
    currentUser.following.pull(userId);
    userToFollow.followers.pull(currentUserId);
    await currentUser.save();
    await userToFollow.save();

    res.status(StatusCodes.OK).json({ message: 'User unfollowed' });
  } else {
    // Follow
    currentUser.following.push(userId);
    userToFollow.followers.push(currentUserId);
    await currentUser.save();
    await userToFollow.save();

    res.status(StatusCodes.OK).json({ message: 'User followed' });
  }
});

// @desc    Get user's followers
// @route   GET /api/users/:userId/followers
// @access  Private
const getFollowers = asyncHandler(async (req, res) => {
  const { userId } = req.params;

  const user = await User.findById(userId)
    .select('followers')
    .populate('followers', 'username profilePicture isOnline');

  if (!user) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('User not found');
  }

  res.status(StatusCodes.OK).json(user.followers);
});

// @desc    Get user's following
// @route   GET /api/users/:userId/following
// @access  Private
const getFollowing = asyncHandler(async (req, res) => {
  const { userId } = req.params;

  const user = await User.findById(userId)
    .select('following')
    .populate('following', 'username profilePicture isOnline');

  if (!user) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('User not found');
  }

  res.status(StatusCodes.OK).json(user.following);
});

module.exports = {
  getUsers,
  getUserProfile,
  updateProfilePicture,
  updateCoverPhoto,
  followUser,
  getFollowers,
  getFollowing,
};