const Story = require('../models/Story');
const User = require('../models/User');
const ErrorResponse = require('../utils/ErrorResponse');
const asyncHandler = require('../middlewares/async');
const { upload } = require('../config/cloudinary');

// @desc    Create story
// @route   POST /api/v1/stories
// @access  Private
exports.createStory = asyncHandler(async (req, res, next) => {
  // Upload file to Cloudinary if present
  let mediaUrl = '';
  let mediaType = 'text';

  if (req.file) {
    mediaUrl = req.file.path;
    mediaType = req.file.mimetype.startsWith('image') ? 'image' : 'video';
  }

  const story = await Story.create({
    user: req.user.id,
    content: req.body.content,
    mediaUrl,
    mediaType,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // Expires in 24 hours
  });

  // Populate user details
  const populatedStory = await Story.findById(story._id).populate('user', 'name username avatar');

  res.status(201).json({
    success: true,
    data: populatedStory
  });
});

// @desc    Get all stories from followed users
// @route   GET /api/v1/stories
// @access  Private
exports.getStories = asyncHandler(async (req, res, next) => {
  // Get current user's following list
  const user = await User.findById(req.user.id).select('following');
  
  // Get stories from followed users that haven't expired
  const stories = await Story.find({
    user: { $in: user.following },
    expiresAt: { $gt: Date.now() }
  })
    .populate('user', 'name username avatar')
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
});

// @desc    Get my stories
// @route   GET /api/v1/stories/me
// @access  Private
exports.getMyStories = asyncHandler(async (req, res, next) => {
  const stories = await Story.find({
    user: req.user.id,
    expiresAt: { $gt: Date.now() }
  })
    .populate('user', 'name username avatar')
    .sort('-createdAt');

  res.status(200).json({
    success: true,
    data: stories
  });
});

// @desc    Get story by ID
// @route   GET /api/v1/stories/:id
// @access  Private
exports.getStory = asyncHandler(async (req, res, next) => {
  const story = await Story.findOne({
    _id: req.params.id,
    expiresAt: { $gt: Date.now() }
  }).populate('user', 'name username avatar');

  if (!story) {
    return next(new ErrorResponse(`Story not found with id of ${req.params.id}`, 404));
  }

  // Check if viewer is following the story owner
  const user = await User.findById(req.user.id).select('following');
  if (!user.following.includes(story.user._id)) {
    return next(new ErrorResponse('Not authorized to view this story', 401));
  }

  // Add viewer to story if not already viewed
  if (!story.viewers.includes(req.user.id)) {
    story.viewers.push(req.user.id);
    await story.save();
  }

  res.status(200).json({
    success: true,
    data: story
  });
});

// @desc    Delete story
// @route   DELETE /api/v1/stories/:id
// @access  Private
exports.deleteStory = asyncHandler(async (req, res, next) => {
  const story = await Story.findOne({
    _id: req.params.id,
    user: req.user.id
  });

  if (!story) {
    return next(new ErrorResponse(`Story not found with id of ${req.params.id}`, 404));
  }

  // Delete media from Cloudinary if exists
  if (story.mediaUrl) {
    const publicId = story.mediaUrl.split('/').pop().split('.')[0];
    await cloudinary.uploader.destroy(`vchat/${publicId}`);
  }

  await story.remove();

  res.status(200).json({
    success: true,
    data: {}
  });
});

// @desc    Get story viewers
// @route   GET /api/v1/stories/:id/viewers
// @access  Private
exports.getStoryViewers = asyncHandler(async (req, res, next) => {
  const story = await Story.findOne({
    _id: req.params.id,
    user: req.user.id
  }).populate('viewers', 'name username avatar');

  if (!story) {
    return next(new ErrorResponse(`Story not found with id of ${req.params.id}`, 404));
  }

  res.status(200).json({
    success: true,
    count: story.viewers.length,
    data: story.viewers
  });
});