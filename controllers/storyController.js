const Story = require('../models/Story');
const ErrorResponse = require('../utils/errorResponse');
const { cloudinary } = require('../config/cloudinary');

// @desc    Create story
// @route   POST /api/stories
// @access  Private
exports.createStory = async (req, res, next) => {
  try {
    const { caption } = req.body;
    
    if (!req.file) {
      return next(new ErrorResponse('Please upload a file', 400));
    }

    const story = await Story.create({
      user: req.user.id,
      media: {
        url: req.file.path,
        type: req.file.mimetype.startsWith('image') ? 'image' : 'video'
      },
      caption
    });

    res.status(201).json({
      success: true,
      data: story
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get all stories from followed users
// @route   GET /api/stories
// @access  Private
exports.getStories = async (req, res, next) => {
  try {
    // Get users that the current user is following
    const user = await User.findById(req.user.id);
    
    const stories = await Story.find({
      user: { $in: user.following },
      expiresAt: { $gt: Date.now() }
    })
      .populate('user', 'username profilePicture')
      .sort('-createdAt');

    // Group stories by user
    const storiesByUser = {};
    stories.forEach(story => {
      if (!storiesByUser[story.user._id]) {
        storiesByUser[story.user._id] = {
          user: story.user,
          stories: []
        };
      }
      storiesByUser[story.user._id].stories.push(story);
    });

    res.status(200).json({
      success: true,
      data: Object.values(storiesByUser)
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get my stories
// @route   GET /api/stories/me
// @access  Private
exports.getMyStories = async (req, res, next) => {
  try {
    const stories = await Story.find({
      user: req.user.id,
      expiresAt: { $gt: Date.now() }
    }).sort('-createdAt');

    res.status(200).json({
      success: true,
      data: stories
    });
  } catch (err) {
    next(err);
  }
};

// @desc    View story
// @route   PUT /api/stories/:storyId/view
// @access  Private
exports.viewStory = async (req, res, next) => {
  try {
    const story = await Story.findById(req.params.storyId);

    if (!story) {
      return next(new ErrorResponse('Story not found', 404));
    }

    // Check if user has already viewed the story
    if (!story.views.includes(req.user.id)) {
      story.views.push(req.user.id);
      await story.save();
    }

    res.status(200).json({
      success: true,
      data: story
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Delete story
// @route   DELETE /api/stories/:storyId
// @access  Private
exports.deleteStory = async (req, res, next) => {
  try {
    const story = await Story.findById(req.params.storyId);

    if (!story) {
      return next(new ErrorResponse('Story not found', 404));
    }

    // Check if user is the owner
    if (story.user.toString() !== req.user.id) {
      return next(new ErrorResponse('Not authorized to delete this story', 401));
    }

    // Delete from Cloudinary
    const publicId = story.media.url.split('/').pop().split('.')[0];
    await cloudinary.uploader.destroy(`vchat/${publicId}`);

    await story.remove();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};