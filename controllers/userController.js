const User = require('../models/User');
const ErrorResponse = require('../utils/errorResponse');
const { upload } = require('../config/cloudinary');

// @desc    Get all users
// @route   GET /api/users
// @access  Private
exports.getUsers = async (req, res, next) => {
  try {
    const users = await User.find().select('-password');

    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get single user
// @route   GET /api/users/:id
// @access  Private
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-password');

    if (!user) {
      return next(
        new ErrorResponse(`User not found with id of ${req.params.id}`, 404)
      );
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update user
// @route   PUT /api/users/:id
// @access  Private
exports.updateUser = async (req, res, next) => {
  try {
    // Check if user is updating their own profile
    if (req.params.id !== req.user.id) {
      return next(new ErrorResponse('Not authorized to update this user', 401));
    }

    const fieldsToUpdate = {
      username: req.body.username,
      email: req.body.email,
      bio: req.body.bio
    };

    const user = await User.findByIdAndUpdate(req.params.id, fieldsToUpdate, {
      new: true,
      runValidators: true
    }).select('-password');

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Upload profile picture
// @route   PUT /api/users/:id/photo
// @access  Private
exports.uploadPhoto = async (req, res, next) => {
  try {
    // Check if user is updating their own profile
    if (req.params.id !== req.user.id) {
      return next(new ErrorResponse('Not authorized to update this user', 401));
    }

    const user = await User.findById(req.params.id);

    if (!user) {
      return next(new ErrorResponse(`User not found with id of ${req.params.id}`, 404));
    }

    if (!req.file) {
      return next(new ErrorResponse('Please upload a file', 400));
    }

    // Delete old photo if not default
    if (user.profilePicture !== 'default.jpg') {
      const publicId = user.profilePicture.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`vchat/${publicId}`);
    }

    user.profilePicture = req.file.path;
    await user.save();

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Follow user
// @route   PUT /api/users/:id/follow
// @access  Private
exports.followUser = async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) {
      return next(new ErrorResponse('You cannot follow yourself', 400));
    }

    const userToFollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user.id);

    if (!userToFollow || !currentUser) {
      return next(new ErrorResponse('User not found', 404));
    }

    // Check if already following
    if (currentUser.following.includes(req.params.id)) {
      return next(new ErrorResponse('You are already following this user', 400));
    }

    currentUser.following.push(req.params.id);
    userToFollow.followers.push(req.user.id);

    await currentUser.save();
    await userToFollow.save();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Unfollow user
// @route   PUT /api/users/:id/unfollow
// @access  Private
exports.unfollowUser = async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) {
      return next(new ErrorResponse('You cannot unfollow yourself', 400));
    }

    const userToUnfollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user.id);

    if (!userToUnfollow || !currentUser) {
      return next(new ErrorResponse('User not found', 404));
    }

    // Check if not following
    if (!currentUser.following.includes(req.params.id)) {
      return next(new ErrorResponse('You are not following this user', 400));
    }

    currentUser.following = currentUser.following.filter(
      id => id.toString() !== req.params.id
    );
    userToUnfollow.followers = userToUnfollow.followers.filter(
      id => id.toString() !== req.user.id
    );

    await currentUser.save();
    await userToUnfollow.save();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get followers
// @route   GET /api/users/:id/followers
// @access  Private
exports.getFollowers = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).populate(
      'followers',
      'username profilePicture'
    );

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    res.status(200).json({
      success: true,
      count: user.followers.length,
      data: user.followers
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get following
// @route   GET /api/users/:id/following
// @access  Private
exports.getFollowing = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).populate(
      'following',
      'username profilePicture'
    );

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    res.status(200).json({
      success: true,
      count: user.following.length,
      data: user.following
    });
  } catch (err) {
    next(err);
  }
};