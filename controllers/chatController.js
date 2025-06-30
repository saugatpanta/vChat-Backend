const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const User = require('../models/User');
const ErrorResponse = require('../utils/ErrorResponse');
const asyncHandler = require('../middlewares/async');

// @desc    Get all conversations for a user
// @route   GET /api/v1/chat/conversations
// @access  Private
exports.getConversations = asyncHandler(async (req, res, next) => {
  const conversations = await Conversation.find({
    participants: { $in: [req.user.id] }
  })
    .populate('participants', 'name username avatar')
    .populate('lastMessage')
    .sort('-updatedAt');

  res.status(200).json({
    success: true,
    count: conversations.length,
    data: conversations
  });
});

// @desc    Get or create conversation
// @route   GET /api/v1/chat/conversations/:userId
// @access  Private
exports.getOrCreateConversation = asyncHandler(async (req, res, next) => {
  const { userId } = req.params;

  // Check if user exists
  const user = await User.findById(userId);
  if (!user) {
    return next(new ErrorResponse(`User not found with id of ${userId}`, 404));
  }

  // Check if conversation already exists
  let conversation = await Conversation.findOne({
    participants: { $all: [req.user.id, userId] },
    isGroup: false
  })
    .populate('participants', 'name username avatar')
    .populate('lastMessage');

  // If conversation doesn't exist, create it
  if (!conversation) {
    conversation = await Conversation.create({
      participants: [req.user.id, userId],
      isGroup: false
    });

    conversation = await Conversation.findById(conversation._id)
      .populate('participants', 'name username avatar')
      .populate('lastMessage');
  }

  res.status(200).json({
    success: true,
    data: conversation
  });
});

// @desc    Get messages for a conversation
// @route   GET /api/v1/chat/conversations/:conversationId/messages
// @access  Private
exports.getMessages = asyncHandler(async (req, res, next) => {
  const { conversationId } = req.params;

  // Check if conversation exists and user is a participant
  const conversation = await Conversation.findOne({
    _id: conversationId,
    participants: { $in: [req.user.id] }
  });

  if (!conversation) {
    return next(new ErrorResponse(`Conversation not found with id of ${conversationId}`, 404));
  }

  const messages = await Message.find({
    conversation: conversationId
  })
    .populate('sender', 'name username avatar')
    .sort('createdAt');

  res.status(200).json({
    success: true,
    count: messages.length,
    data: messages
  });
});

// @desc    Send message
// @route   POST /api/v1/chat/conversations/:conversationId/messages
// @access  Private
exports.sendMessage = asyncHandler(async (req, res, next) => {
  const { conversationId } = req.params;
  const { content, type } = req.body;

  // Check if conversation exists and user is a participant
  const conversation = await Conversation.findOne({
    _id: conversationId,
    participants: { $in: [req.user.id] }
  });

  if (!conversation) {
    return next(new ErrorResponse(`Conversation not found with id of ${conversationId}`, 404));
  }

  // Create message
  const message = await Message.create({
    conversation: conversationId,
    sender: req.user.id,
    content,
    type: type || 'text'
  });

  // Update conversation last message
  conversation.lastMessage = message._id;
  await conversation.save();

  // Populate sender and conversation
  const populatedMessage = await Message.findById(message._id)
    .populate('sender', 'name username avatar')
    .populate('conversation');

  // Emit message to socket
  req.io.to(conversationId).emit('newMessage', populatedMessage);

  res.status(201).json({
    success: true,
    data: populatedMessage
  });
});

// @desc    Create group conversation
// @route   POST /api/v1/chat/conversations/group
// @access  Private
exports.createGroupConversation = asyncHandler(async (req, res, next) => {
  const { name, participants } = req.body;

  if (!name || !participants || participants.length < 2) {
    return next(new ErrorResponse('Please provide name and at least 2 participants', 400));
  }

  // Add current user to participants if not already included
  if (!participants.includes(req.user.id.toString())) {
    participants.push(req.user.id.toString());
  }

  // Check if all participants exist
  const users = await User.find({ _id: { $in: participants } });
  if (users.length !== participants.length) {
    return next(new ErrorResponse('One or more participants not found', 404));
  }

  // Create group conversation
  const conversation = await Conversation.create({
    participants,
    isGroup: true,
    groupName: name,
    groupAdmin: req.user.id
  });

  const populatedConversation = await Conversation.findById(conversation._id)
    .populate('participants', 'name username avatar')
    .populate('lastMessage');

  // Emit new conversation to all participants
  participants.forEach(participantId => {
    req.io.to(participantId.toString()).emit('newConversation', populatedConversation);
  });

  res.status(201).json({
    success: true,
    data: populatedConversation
  });
});

// @desc    Update group conversation
// @route   PUT /api/v1/chat/conversations/group/:conversationId
// @access  Private
exports.updateGroupConversation = asyncHandler(async (req, res, next) => {
  const { conversationId } = req.params;
  const { name, participants } = req.body;

  // Check if conversation exists and is a group
  const conversation = await Conversation.findOne({
    _id: conversationId,
    isGroup: true,
    groupAdmin: req.user.id
  });

  if (!conversation) {
    return next(new ErrorResponse(`Group conversation not found with id of ${conversationId}`, 404));
  }

  // Update group name if provided
  if (name) {
    conversation.groupName = name;
  }

  // Update participants if provided
  if (participants && participants.length > 0) {
    // Check if all new participants exist
    const users = await User.find({ _id: { $in: participants } });
    if (users.length !== participants.length) {
      return next(new ErrorResponse('One or more participants not found', 404));
    }

    // Add current user to participants if not already included
    if (!participants.includes(req.user.id.toString())) {
      participants.push(req.user.id.toString());
    }

    conversation.participants = participants;
  }

  await conversation.save();

  const populatedConversation = await Conversation.findById(conversation._id)
    .populate('participants', 'name username avatar')
    .populate('lastMessage');

  // Emit updated conversation to all participants
  populatedConversation.participants.forEach(participant => {
    req.io.to(participant._id.toString()).emit('updatedConversation', populatedConversation);
  });

  res.status(200).json({
    success: true,
    data: populatedConversation
  });
});

// @desc    Delete message
// @route   DELETE /api/v1/chat/messages/:messageId
// @access  Private
exports.deleteMessage = asyncHandler(async (req, res, next) => {
  const { messageId } = req.params;

  const message = await Message.findOne({
    _id: messageId,
    sender: req.user.id
  });

  if (!message) {
    return next(new ErrorResponse(`Message not found with id of ${messageId}`, 404));
  }

  await message.remove();

  // Emit deleted message to conversation
  req.io.to(message.conversation.toString()).emit('deletedMessage', messageId);

  res.status(200).json({
    success: true,
    data: {}
  });
});

// @desc    Start video call
// @route   POST /api/v1/chat/conversations/:conversationId/call
// @access  Private
exports.startVideoCall = asyncHandler(async (req, res, next) => {
  const { conversationId } = req.params;
  const { type } = req.body; // 'video' or 'audio'

  // Check if conversation exists and user is a participant
  const conversation = await Conversation.findOne({
    _id: conversationId,
    participants: { $in: [req.user.id] }
  }).populate('participants', 'name username avatar');

  if (!conversation) {
    return next(new ErrorResponse(`Conversation not found with id of ${conversationId}`, 404));
  }

  // Create call data
  const callData = {
    conversation: conversationId,
    caller: req.user.id,
    type: type || 'video',
    participants: conversation.participants.map(p => p._id),
    status: 'calling'
  };

  // Emit call to other participants
  conversation.participants.forEach(participant => {
    if (participant._id.toString() !== req.user.id.toString()) {
      req.io.to(participant._id.toString()).emit('incomingCall', callData);
    }
  });

  res.status(200).json({
    success: true,
    data: callData
  });
});

// @desc    End video call
// @route   POST /api/v1/chat/conversations/:conversationId/call/end
// @access  Private
exports.endVideoCall = asyncHandler(async (req, res, next) => {
  const { conversationId } = req.params;
  const { callId } = req.body;

  // Check if conversation exists and user is a participant
  const conversation = await Conversation.findOne({
    _id: conversationId,
    participants: { $in: [req.user.id] }
  }).populate('participants', 'name username avatar');

  if (!conversation) {
    return next(new ErrorResponse(`Conversation not found with id of ${conversationId}`, 404));
  }

  // Emit call ended to all participants
  conversation.participants.forEach(participant => {
    req.io.to(participant._id.toString()).emit('callEnded', {
      callId,
      endedBy: req.user.id
    });
  });

  res.status(200).json({
    success: true,
    data: {}
  });
});