const User = require('../models/User');
const { upload } = require('../config/cloudinary');

// @desc    Get user profile
// @route   GET /api/users/:id
// @access  Public
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update user profile
// @route   PUT /api/users/:id
// @access  Private
exports.updateUser = async (req, res, next) => {
  try {
    const { username, bio, status } = req.body;
    let avatarUrl = '';

    if (req.files && req.files.avatar) {
      const result = await upload.single('avatar')(req, res);
      avatarUrl = result.file.path;
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      {
        username,
        bio,
        status,
        ...(avatarUrl && { avatar: avatarUrl })
      },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Check ownership
    if (user._id.toString() !== req.user.id) {
      return res.status(401).json({
        success: false,
        error: 'Not authorized to update this user'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Follow user
// @route   POST /api/users/:id/follow
// @access  Private
exports.followUser = async (req, res, next) => {
  try {
    const userToFollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user.id);

    if (!userToFollow) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Check if already following
    if (currentUser.following.includes(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: 'Already following this user'
      });
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
  } catch (err) {
    next(err);
  }
};

// @desc    Unfollow user
// @route   POST /api/users/:id/unfollow
// @access  Private
exports.unfollowUser = async (req, res, next) => {
  try {
    const userToUnfollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user.id);

    if (!userToUnfollow) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Check if not following
    if (!currentUser.following.includes(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: 'Not following this user'
      });
    }

    // Remove from following list
    currentUser.following = currentUser.following.filter(
      id => id.toString() !== req.params.id
    );
    await currentUser.save();

    // Remove from followers list
    userToUnfollow.followers = userToUnfollow.followers.filter(
      id => id.toString() !== req.user.id
    );
    await userToUnfollow.save();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Search users
// @route   GET /api/users/search/:query
// @access  Public
exports.searchUsers = async (req, res, next) => {
  try {
    const users = await User.find({
      $or: [
        { username: { $regex: req.params.query, $options: 'i' } },
        { email: { $regex: req.params.query, $options: 'i' } }
      ]
    }).select('-password');

    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get user suggestions
// @route   GET /api/users/suggestions
// @access  Private
exports.getSuggestions = async (req, res, next) => {
  try {
    const currentUser = await User.findById(req.user.id);
    const followingIds = currentUser.following.map(id => id.toString());
    followingIds.push(req.user.id); // Exclude self

    // Get random users not already followed
    const suggestions = await User.aggregate([
      { $match: { _id: { $nin: followingIds.map(id => mongoose.Types.ObjectId(id)) } } },
      { $sample: { size: 5 } },
      { $project: { password: 0 } }
    ]);

    res.status(200).json({
      success: true,
      count: suggestions.length,
      data: suggestions
    });
  } catch (err) {
    next(err);
  }
};