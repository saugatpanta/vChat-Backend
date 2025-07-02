const Story = require('../models/Story');
const User = require('../models/User');
const { upload } = require('../config/cloudinary');

// @desc    Create story
// @route   POST /api/stories
// @access  Private
exports.createStory = async (req, res, next) => {
  try {
    const { text, isMedia, duration } = req.body;
    let mediaUrl = '';

    if (isMedia && req.files) {
      const result = await upload.single('media')(req, res);
      mediaUrl = result.file.path;
    }

    const story = new Story({
      user: req.user.id,
      text: text || '',
      media: mediaUrl || undefined,
      isMedia: !!mediaUrl,
      duration: duration || 24 // Default 24 hours
    });

    await story.save();

    res.status(201).json({
      success: true,
      data: story
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get stories from followed users
// @route   GET /api/stories
// @access  Private
exports.getStories = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).populate('following', '_id');

    const followingIds = user.following.map(follow => follow._id);
    followingIds.push(req.user.id); // Include user's own stories

    const stories = await Story.find({
      user: { $in: followingIds },
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
    })
      .populate('user', 'username avatar')
      .sort({ createdAt: -1 });

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

// @desc    Get story by ID
// @route   GET /api/stories/:id
// @access  Private
exports.getStory = async (req, res, next) => {
  try {
    const story = await Story.findById(req.params.id).populate(
      'user',
      'username avatar'
    );

    if (!story) {
      return res.status(404).json({
        success: false,
        error: 'Story not found'
      });
    }

    // Check if story is expired
    if (new Date(story.createdAt).getTime() + story.duration * 60 * 60 * 1000 < Date.now()) {
      return res.status(404).json({
        success: false,
        error: 'Story has expired'
      });
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
// @route   DELETE /api/stories/:id
// @access  Private
exports.deleteStory = async (req, res, next) => {
  try {
    const story = await Story.findById(req.params.id);

    if (!story) {
      return res.status(404).json({
        success: false,
        error: 'Story not found'
      });
    }

    // Check ownership
    if (story.user.toString() !== req.user.id) {
      return res.status(401).json({
        success: false,
        error: 'Not authorized to delete this story'
      });
    }

    await story.remove();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
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
        error: 'Story not found'
      });
    }

    // Check if story is expired
    if (new Date(story.createdAt).getTime() + story.duration * 60 * 60 * 1000 < Date.now()) {
      return res.status(404).json({
        success: false,
        error: 'Story has expired'
      });
    }

    // Check if user has already viewed the story
    if (!story.viewers.includes(req.user.id)) {
      story.viewers.push(req.user.id);
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