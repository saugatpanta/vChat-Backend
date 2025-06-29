const User = require('../models/User');
const logger = require('../middlewares/logger');
const { uploadToCloudinary, deleteFromCloudinary } = require('../config/cloudinary');

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
exports.getUsers = async (req, res, next) => {
  try {
    const users = await User.find().select('-password');

    res.status(200).json({
      success: true,
      count: users.length,
      users,
    });
  } catch (error) {
    logger.error(`User Controller - Get Users Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get single user
// @route   GET /api/users/:id
// @access  Private
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    logger.error(`User Controller - Get User Error: ${error.message}`);
    next(error);
  }
};

// @desc    Update user profile
// @route   PUT /api/users/profile
// @access  Private
exports.updateProfile = async (req, res, next) => {
  try {
    const { username, bio, phone } = req.body;
    const userId = req.user.id;

    const updateFields = {
      username,
      bio,
      phone,
    };

    // Handle profile photo upload
    if (req.files && req.files.profilePhoto) {
      const user = await User.findById(userId);

      // Delete old photo if exists
      if (user.profilePhoto && user.profilePhoto.publicId) {
        await deleteFromCloudinary(user.profilePhoto.publicId);
      }

      // Upload new photo
      const file = req.files.profilePhoto;
      const result = await uploadToCloudinary(file.tempFilePath, 'vchat/profiles');

      updateFields.profilePhoto = {
        url: result.url,
        publicId: result.public_id,
      };
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updateFields, {
      new: true,
      runValidators: true,
    }).select('-password');

    res.status(200).json({
      success: true,
      user: updatedUser,
    });
  } catch (error) {
    logger.error(`User Controller - Update Profile Error: ${error.message}`);
    next(error);
  }
};

// @desc    Follow user
// @route   PUT /api/users/follow/:id
// @access  Private
exports.followUser = async (req, res, next) => {
  try {
    const userToFollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user.id);

    if (!userToFollow) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Check if already following
    if (
      currentUser.following.some(
        user => user._id.toString() === userToFollow._id.toString()
      )
    ) {
      return res.status(400).json({
        success: false,
        message: 'Already following this user',
      });
    }

    // Add to following list
    currentUser.following.push(userToFollow._id);
    await currentUser.save();

    // Add to followers list
    userToFollow.followers.push(currentUser._id);
    await userToFollow.save();

    res.status(200).json({
      success: true,
      message: 'User followed successfully',
    });
  } catch (error) {
    logger.error(`User Controller - Follow User Error: ${error.message}`);
    next(error);
  }
};

// @desc    Unfollow user
// @route   PUT /api/users/unfollow/:id
// @access  Private
exports.unfollowUser = async (req, res, next) => {
  try {
    const userToUnfollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user.id);

    if (!userToUnfollow) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Check if not following
    if (
      !currentUser.following.some(
        user => user._id.toString() === userToUnfollow._id.toString()
      )
    ) {
      return res.status(400).json({
        success: false,
        message: 'Not following this user',
      });
    }

    // Remove from following list
    currentUser.following = currentUser.following.filter(
      user => user._id.toString() !== userToUnfollow._id.toString()
    );
    await currentUser.save();

    // Remove from followers list
    userToUnfollow.followers = userToUnfollow.followers.filter(
      user => user._id.toString() !== currentUser._id.toString()
    );
    await userToUnfollow.save();

    res.status(200).json({
      success: true,
      message: 'User unfollowed successfully',
    });
  } catch (error) {
    logger.error(`User Controller - Unfollow User Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get user's followers
// @route   GET /api/users/followers/:id
// @access  Private
exports.getFollowers = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id)
      .select('followers')
      .populate('followers', 'username profilePhoto');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    res.status(200).json({
      success: true,
      count: user.followers.length,
      followers: user.followers,
    });
  } catch (error) {
    logger.error(`User Controller - Get Followers Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get user's following
// @route   GET /api/users/following/:id
// @access  Private
exports.getFollowing = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id)
      .select('following')
      .populate('following', 'username profilePhoto');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    res.status(200).json({
      success: true,
      count: user.following.length,
      following: user.following,
    });
  } catch (error) {
    logger.error(`User Controller - Get Following Error: ${error.message}`);
    next(error);
  }
};

// @desc    Delete user account
// @route   DELETE /api/users
// @access  Private
exports.deleteAccount = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Delete profile photo if exists
    if (user.profilePhoto && user.profilePhoto.publicId) {
      await deleteFromCloudinary(user.profilePhoto.publicId);
    }

    await user.remove();

    res.status(200).json({
      success: true,
      message: 'Account deleted successfully',
    });
  } catch (error) {
    logger.error(`User Controller - Delete Account Error: ${error.message}`);
    next(error);
  }
};