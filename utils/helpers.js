const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Generate JWT token
exports.generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  });
};

// Verify JWT token
exports.verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

// Generate random string
exports.generateRandomString = (length) => {
  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
};

// Format user object
exports.formatUser = (user) => {
  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    username: user.username,
    avatar: user.avatar,
    verified: user.verified,
    bio: user.bio,
    website: user.website,
    gender: user.gender,
    followers: user.followers,
    following: user.following,
    createdAt: user.createdAt
  };
};

// Format message object
exports.formatMessage = (message) => {
  return {
    _id: message._id,
    conversation: message.conversation,
    sender: message.sender,
    content: message.content,
    type: message.type,
    readBy: message.readBy,
    createdAt: message.createdAt,
    updatedAt: message.updatedAt
  };
};

// Format conversation object
exports.formatConversation = (conversation) => {
  return {
    _id: conversation._id,
    participants: conversation.participants,
    isGroup: conversation.isGroup,
    groupName: conversation.groupName,
    groupAdmin: conversation.groupAdmin,
    groupImage: conversation.groupImage,
    lastMessage: conversation.lastMessage,
    createdAt: conversation.createdAt,
    updatedAt: conversation.updatedAt
  };
};

// Format story object
exports.formatStory = (story) => {
  return {
    _id: story._id,
    user: story.user,
    content: story.content,
    mediaUrl: story.mediaUrl,
    mediaType: story.mediaType,
    viewers: story.viewers,
    expiresAt: story.expiresAt,
    createdAt: story.createdAt
  };
};

// Async handler to wrap routes for error handling
exports.asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};