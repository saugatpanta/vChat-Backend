const asyncHandler = require('express-async-handler');
const { StatusCodes } = require('http-status-codes');
const Story = require('../models/Story');
const User = require('../models/User');
const { cloudinary } = require('../config/cloudinary');
const logger = require('../middlewares/logger');

// @desc    Create a new story
// @route   POST /api/stories
// @access  Private
const createStory = asyncHandler(async (req, res) => {
  const { caption, location } = req.body;
  const userId = req.user._id;

  if (!req.file) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please upload a file');
  }

  // Upload file to Cloudinary
  const result = await cloudinary.uploader.upload(req.file.path, {
    resource_type: 'auto',
    folder: 'vchat/stories',
  });

  const story = await Story.create({
    user: userId,
    media: {
      url: result.secure_url,
      type: result.resource_type,
      duration: result.resource_type === 'video' ? Math.min(result.duration, 15) : 7,
    },
    caption,
    location,
  });

  const populatedStory = await Story.findById(story._id).populate(
    'user',
    'username profilePicture'
  );

  logger.info(`New story created by ${req.user.username}`);

  res.status(StatusCodes.CREATED).json(populatedStory);
});

// @desc    Get stories from users you follow
// @route   GET /api/stories
// @access  Private
const getStories = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  // Get users you follow
  const user = await User.findById(userId).select('following');
  const followingIds = user.following.map(id => id.toString());

  // Add your own stories
  followingIds.push(userId.toString());

  const stories = await Story.find({
    user: { $in: followingIds },
    expiresAt: { $gt: new Date() },
  })
    .populate('user', 'username profilePicture')
    .sort('-createdAt');

  // Group stories by user
  const storiesByUser = stories.reduce((acc, story) => {
    const userId = story.user._id.toString();
    if (!acc[userId]) {
      acc[userId] = {
        user: story.user,
        stories: [],
        viewed: story.views.some(view => view.user.toString() === req.user._id.toString()),
      };
    }
    acc[userId].stories.push(story);
    return acc;
  }, {});

  res.status(StatusCodes.OK).json(Object.values(storiesByUser));
});

// @desc    Get a specific story
// @route   GET /api/stories/:storyId
// @access  Private
const getStory = asyncHandler(async (req, res) => {
  const { storyId } = req.params;
  const userId = req.user._id;

  const story = await Story.findOne({
    _id: storyId,
    expiresAt: { $gt: new Date() },
  }).populate('user', 'username profilePicture');

  if (!story) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Story not found or expired');
  }

  // Check if user has already viewed the story
  const hasViewed = story.views.some(
    (view) => view.user.toString() === userId.toString()
  );

  if (!hasViewed) {
    story.views.push({ user: userId });
    await story.save();
  }

  res.status(StatusCodes.OK).json(story);
});

// @desc    Delete a story
// @route   DELETE /api/stories/:storyId
// @access  Private
const deleteStory = asyncHandler(async (req, res) => {
  const { storyId } = req.params;
  const userId = req.user._id;

  const story = await Story.findOne({
    _id: storyId,
    user: userId,
  });

  if (!story) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Story not found or not authorized');
  }

  // Delete from Cloudinary
  const publicId = story.media.url.split('/').pop().split('.')[0];
  await cloudinary.uploader.destroy(`vchat/stories/${publicId}`, {
    resource_type: story.media.type === 'video' ? 'video' : 'image',
  });

  await story.remove();

  logger.info(`Story deleted by ${req.user.username}`);

  res.status(StatusCodes.OK).json({ success: true });
});

// @desc    Get my stories
// @route   GET /api/stories/me
// @access  Private
const getMyStories = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  const stories = await Story.find({
    user: userId,
    expiresAt: { $gt: new Date() },
  }).sort('-createdAt');

  res.status(StatusCodes.OK).json(stories);
});

module.exports = {
  createStory,
  getStories,
  getStory,
  deleteStory,
  getMyStories,
};