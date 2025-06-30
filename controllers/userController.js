const User = require('../models/User');
const ErrorResponse = require('../utils/ErrorResponse');
const asyncHandler = require('../middlewares/async');
const { upload } = require('../config/cloudinary');

// @desc    Get all users
// @route   GET /api/v1/users
// @access  Private
exports.getUsers = asyncHandler(async (req, res, next) => {
  // Exclude current user and add search functionality
  const keyword = req.query.search
    ? {
        $or: [
          { name: { $regex: req.query.search, $options: 'i' } },
          { username: { $regex: req.query.search, $options: 'i' } }
        ]
      }
    : {};

  const users = await User.find({ ...keyword, _id: { $ne: req.user.id } })
    .select('name username avatar verified')
    .limit(10);

  res.status(200).json({
    success: true,
    count: users.length,
    data: users
  });
});

// @desc    Get single user
// @route   GET /api/v1/users/:id
// @access  Private
exports.getUser = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id).select(
    'name username avatar bio website gender followers following verified createdAt'
  );

  if (!user) {
    return next(new ErrorResponse(`User not found with id of ${req.params.id}`, 404));
  }

  res.status(200).json({
    success: true,
    data: user
  });
});

// @desc    Update user
// @route   PUT /api/v1/users/:id
// @access  Private
exports.updateUser = asyncHandler(async (req, res, next) => {
  // Make sure user is updating their own profile
  if (req.params.id !== req.user.id) {
    return next(new ErrorResponse(`Not authorized to update this user`, 401));
  }

  const fieldsToUpdate = {
    name: req.body.name,
    username: req.body.username,
    bio: req.body.bio,
    website: req.body.website,
    gender: req.body.gender
  };

  const user = await User.findByIdAndUpdate(req.params.id, fieldsToUpdate, {
    new: true,
    runValidators: true
  });

  res.status(200).json({
    success: true,
    data: user
  });
});

// @desc    Update user avatar
// @route   PUT /api/v1/users/:id/avatar
// @access  Private
exports.updateAvatar = asyncHandler(async (req, res, next) => {
  // Make sure user is updating their own profile
  if (req.params.id !== req.user.id) {
    return next(new ErrorResponse(`Not authorized to update this user`, 401));
  }

  if (!req.file) {
    return next(new ErrorResponse(`Please upload an image file`, 400));
  }

  const user = await User.findById(req.params.id);

  // Delete old avatar from Cloudinary if exists
  if (user.avatar) {
    const publicId = user.avatar.split('/').pop().split('.')[0];
    await cloudinary.uploader.destroy(`vchat/${publicId}`);
  }

  user.avatar = req.file.path;
  await user.save();

  res.status(200).json({
    success: true,
    data: user
  });
});

// @desc    Follow user
// @route   PUT /api/v1/users/:id/follow
// @access  Private
exports.followUser = asyncHandler(async (req, res, next) => {
  if (req.params.id === req.user.id) {
    return next(new ErrorResponse(`You cannot follow yourself`, 400));
  }

  const userToFollow = await User.findById(req.params.id);
  const currentUser = await User.findById(req.user.id);

  if (!userToFollow) {
    return next(new ErrorResponse(`User not found with id of ${req.params.id}`, 404));
  }

  // Check if already following
  if (currentUser.following.includes(req.params.id)) {
    return next(new ErrorResponse(`You are already following this user`, 400));
  }

  // Add to following list
  currentUser.following.push(req.params.id);
  await currentUser.save();

  // Add to followers list
  userToFollow.followers.push(req.user.id);
  await userToFollow.save();

  res.status(200).json({
    success: true,
    data: {}
  });
});

// @desc    Unfollow user
// @route   PUT /api/v1/users/:id/unfollow
// @access  Private
exports.unfollowUser = asyncHandler(async (req, res, next) => {
  if (req.params.id === req.user.id) {
    return next(new ErrorResponse(`You cannot unfollow yourself`, 400));
  }

  const userToUnfollow = await User.findById(req.params.id);
  const currentUser = await User.findById(req.user.id);

  if (!userToUnfollow) {
    return next(new ErrorResponse(`User not found with id of ${req.params.id}`, 404));
  }

  // Check if not following
  if (!currentUser.following.includes(req.params.id)) {
    return next(new ErrorResponse(`You are not following this user`, 400));
  }

  // Remove from following list
  currentUser.following = currentUser.following.filter(
    id => id.toString() !== req.params.id.toString()
  );
  await currentUser.save();

  // Remove from followers list
  userToUnfollow.followers = userToUnfollow.followers.filter(
    id => id.toString() !== req.user.id.toString()
  );
  await userToUnfollow.save();

  res.status(200).json({
    success: true,
    data: {}
  });
});

// @desc    Get user followers
// @route   GET /api/v1/users/:id/followers
// @access  Private
exports.getFollowers = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id).populate(
    'followers',
    'name username avatar verified'
  );

  if (!user) {
    return next(new ErrorResponse(`User not found with id of ${req.params.id}`, 404));
  }

  res.status(200).json({
    success: true,
    count: user.followers.length,
    data: user.followers
  });
});

// @desc    Get user following
// @route   GET /api/v1/users/:id/following
// @access  Private
exports.getFollowing = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id).populate(
    'following',
    'name username avatar verified'
  );

  if (!user) {
    return next(new ErrorResponse(`User not found with id of ${req.params.id}`, 404));
  }

  res.status(200).json({
    success: true,
    count: user.following.length,
    data: user.following
  });
});