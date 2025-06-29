const Story = require('../models/Story');
const User = require('../models/User');
const logger = require('../middlewares/logger');
const { uploadToCloudinary, deleteFromCloudinary } = require('../config/cloudinary');

// @desc    Create story
// @route   POST /api/stories
// @access  Private
exports.createStory = async (req, res, next) => {
  try {
    const { type, duration = 24, caption = '' } = req.body;

    if (!req.files || !req.files.file) {
      return res.status(400).json({
        success: false,
        message: 'Please upload a file',
      });
    }

    const file = req.files.file;

    // Upload to Cloudinary
    const result = await uploadToCloudinary(file.tempFilePath, 'vchat/stories');

    // Create story
    const story = await Story.create({
      user: req.user.id,
      media: {
        url: result.url,
        publicId: result.public_id,
        type: type || (file.mimetype.startsWith('image') ? 'image' : 'video'),
      },
      caption,
      duration,
    });

    res.status(201).json({
      success: true,
      story,
    });
  } catch (error) {
    logger.error(`Story Controller - Create Story Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get all stories from followed users
// @route   GET /api/stories
// @access  Private
exports.getStories = async (req, res, next) => {
  try {
    // Get current user's following list
    const currentUser = await User.findById(req.user.id);
    const followingIds = currentUser.following.map(user => user._id);

    // Add current user's ID to see their own stories
    followingIds.push(req.user.id);

    // Get stories from the last 24 hours
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const stories = await Story.find({
      user: { $in: followingIds },
      createdAt: { $gte: twentyFourHoursAgo },
    })
      .populate('user', 'username profilePhoto')
      .sort('-createdAt');

    // Group stories by user
    const storiesByUser = {};
    stories.forEach(story => {
      if (!storiesByUser[story.user._id]) {
        storiesByUser[story.user._id] = {
          user: story.user,
          stories: [],
        };
      }
      storiesByUser[story.user._id].stories.push(story);
    });

    res.status(200).json({
      success: true,
      count: stories.length,
      stories: Object.values(storiesByUser),
    });
  } catch (error) {
    logger.error(`Story Controller - Get Stories Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get single story
// @route   GET /api/stories/:id
// @access  Private
exports.getStory = async (req, res, next) => {
  try {
    const story = await Story.findById(req.params.id).populate(
      'user',
      'username profilePhoto'
    );

    if (!story) {
      return res.status(404).json({
        success: false,
        message: 'Story not found',
      });
    }

    // Check if story is expired
    const storyAge = (Date.now() - story.createdAt) / (1000 * 60 * 60);
    if (storyAge > story.duration) {
      return res.status(404).json({
        success: false,
        message: 'Story has expired',
      });
    }

    res.status(200).json({
      success: true,
      story,
    });
  } catch (error) {
    logger.error(`Story Controller - Get Story Error: ${error.message}`);
    next(error);
  }
};

// @desc    Delete story
// @route   DELETE /api/stories/:id
// @access  Private
exports.deleteStory = async (req, res, next) => {
  try {
    const story = await Story.findById(req.params.id);

    if (!story) {
      return res.status(404).json({
        success: false,
        message: 'Story not found',
      });
    }

    // Check if user is the owner
    if (story.user.toString() !== req.user.id) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to delete this story',
      });
    }

    // Delete media from Cloudinary
    if (story.media && story.media.publicId) {
      await deleteFromCloudinary(story.media.publicId);
    }

    await story.remove();

    res.status(200).json({
      success: true,
      message: 'Story deleted',
    });
  } catch (error) {
    logger.error(`Story Controller - Delete Story Error: ${error.message}`);
    next(error);
  }
};

// @desc    View story
// @route   POST /api/stories/:id/view
// @access  Private
exports.viewStory = async (req, res, next) => {
  try {
    const story = await Story.findById(req.params.id);

    if (!story) {
      return res.status(404).json({
        success: false,
        message: 'Story not found',
      });
    }

    // Check if story is expired
    const storyAge = (Date.now() - story.createdAt) / (1000 * 60 * 60);
    if (storyAge > story.duration) {
      return res.status(404).json({
        success: false,
        message: 'Story has expired',
      });
    }

    // Check if user has already viewed the story
    if (!story.views.includes(req.user.id)) {
      story.views.push(req.user.id);
      await story.save();
    }

    res.status(200).json({
      success: true,
      message: 'Story viewed',
    });
  } catch (error) {
    logger.error(`Story Controller - View Story Error: ${error.message}`);
    next(error);
  }
};

// @desc    React to story
// @route   POST /api/stories/:id/react
// @access  Private
exports.reactToStory = async (req, res, next) => {
  try {
    const { reaction } = req.body;
    const story = await Story.findById(req.params.id);

    if (!story) {
      return res.status(404).json({
        success: false,
        message: 'Story not found',
      });
    }

    // Check if story is expired
    const storyAge = (Date.now() - story.createdAt) / (1000 * 60 * 60);
    if (storyAge > story.duration) {
      return res.status(404).json({
        success: false,
        message: 'Story has expired',
      });
    }

    // Check if user has already reacted
    const existingReactionIndex = story.reactions.findIndex(
      r => r.user.toString() === req.user.id
    );

    if (existingReactionIndex >= 0) {
      // Update existing reaction
      story.reactions[existingReactionIndex].reaction = reaction;
    } else {
      // Add new reaction
      story.reactions.push({
        user: req.user.id,
        reaction,
      });
    }

    await story.save();

    res.status(200).json({
      success: true,
      message: 'Reaction added',
    });
  } catch (error) {
    logger.error(`Story Controller - React to Story Error: ${error.message}`);
    next(error);
  }
};