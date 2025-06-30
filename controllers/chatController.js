const asyncHandler = require('express-async-handler');
const { StatusCodes } = require('http-status-codes');
const User = require('../models/User');
const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const logger = require('../middlewares/logger');

// @desc    Get all conversations for a user
// @route   GET /api/chat/conversations
// @access  Private
const getConversations = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  const conversations = await Conversation.find({
    participants: { $in: [userId] },
  })
    .populate('participants', 'username profilePicture isOnline')
    .populate('lastMessage')
    .sort('-updatedAt');

  res.status(StatusCodes.OK).json(conversations);
});

// @desc    Get or create a conversation
// @route   POST /api/chat/conversations
// @access  Private
const createConversation = asyncHandler(async (req, res) => {
  const { participantId } = req.body;
  const userId = req.user._id;

  if (!participantId) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide participant ID');
  }

  if (participantId === userId.toString()) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Cannot create conversation with yourself');
  }

  // Check if conversation already exists
  let conversation = await Conversation.findOne({
    participants: { $all: [userId, participantId], $size: 2 },
    isGroup: false,
  })
    .populate('participants', 'username profilePicture isOnline')
    .populate('lastMessage');

  if (!conversation) {
    // Create new conversation
    conversation = await Conversation.create({
      participants: [userId, participantId],
    });

    conversation = await Conversation.findById(conversation._id)
      .populate('participants', 'username profilePicture isOnline');
  }

  res.status(StatusCodes.OK).json(conversation);
});

// @desc    Create a group conversation
// @route   POST /api/chat/conversations/group
// @access  Private
const createGroupConversation = asyncHandler(async (req, res) => {
  const { name, participants } = req.body;
  const userId = req.user._id;

  if (!name || !participants || participants.length < 2) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide group name and at least 2 participants');
  }

  // Add current user to participants if not already included
  if (!participants.includes(userId.toString())) {
    participants.push(userId.toString());
  }

  // Check for duplicate participants
  const uniqueParticipants = [...new Set(participants)];

  const conversation = await Conversation.create({
    participants: uniqueParticipants,
    isGroup: true,
    groupName: name,
    groupAdmin: userId,
  });

  const populatedConversation = await Conversation.findById(conversation._id)
    .populate('participants', 'username profilePicture isOnline');

  res.status(StatusCodes.CREATED).json(populatedConversation);
});

// @desc    Get messages for a conversation
// @route   GET /api/chat/conversations/:conversationId/messages
// @access  Private
const getMessages = asyncHandler(async (req, res) => {
  const { conversationId } = req.params;
  const userId = req.user._id;

  // Check if user is part of the conversation
  const conversation = await Conversation.findOne({
    _id: conversationId,
    participants: { $in: [userId] },
  });

  if (!conversation) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Conversation not found');
  }

  const messages = await Message.find({
    conversation: conversationId,
    deletedFor: { $ne: userId },
  })
    .sort('createdAt')
    .populate('sender', 'username profilePicture');

  // Mark messages as read
  await Message.updateMany(
    {
      conversation: conversationId,
      recipient: userId,
      isRead: false,
    },
    { $set: { isRead: true, readAt: Date.now() } }
  );

  res.status(StatusCodes.OK).json(messages);
});

// @desc    Send a message
// @route   POST /api/chat/conversations/:conversationId/messages
// @access  Private
const sendMessage = asyncHandler(async (req, res) => {
  const { conversationId } = req.params;
  const { text, media } = req.body;
  const userId = req.user._id;

  if (!text && (!media || media.length === 0)) {
    res.status(StatusCodes.BAD_REQUEST);
    throw new Error('Please provide message text or media');
  }

  // Check if user is part of the conversation
  const conversation = await Conversation.findOne({
    _id: conversationId,
    participants: { $in: [userId] },
  }).populate('participants', '_id');

  if (!conversation) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Conversation not found');
  }

  // Get recipient (for 1:1 chat)
  let recipientId;
  if (!conversation.isGroup) {
    recipientId = conversation.participants.find(
      (participant) => participant._id.toString() !== userId.toString()
    )._id;
  }

  const message = await Message.create({
    conversation: conversationId,
    sender: userId,
    recipient: recipientId,
    text,
    media,
  });

  // Update conversation last message
  conversation.lastMessage = message._id;
  await conversation.save();

  const populatedMessage = await Message.findById(message._id)
    .populate('sender', 'username profilePicture');

  // Emit socket event
  req.io.to(conversationId).emit('newMessage', populatedMessage);

  res.status(StatusCodes.CREATED).json(populatedMessage);
});

// @desc    Delete a message
// @route   DELETE /api/chat/messages/:messageId
// @access  Private
const deleteMessage = asyncHandler(async (req, res) => {
  const { messageId } = req.params;
  const userId = req.user._id;

  const message = await Message.findById(messageId);

  if (!message) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Message not found');
  }

  // Check if user is sender or admin
  if (
    message.sender.toString() !== userId.toString() &&
    !(await Conversation.findOne({
      _id: message.conversation,
      isGroup: true,
      groupAdmin: userId,
    }))
  ) {
    res.status(StatusCodes.UNAUTHORIZED);
    throw new Error('Not authorized to delete this message');
  }

  // For everyone or just for me?
  if (req.query.for === 'me') {
    // Delete only for me
    if (!message.deletedFor.includes(userId)) {
      message.deletedFor.push(userId);
      await message.save();
    }
  } else {
    // Delete for everyone
    await Message.deleteOne({ _id: messageId });
    
    // Emit socket event
    req.io.to(message.conversation.toString()).emit('deleteMessage', messageId);
  }

  res.status(StatusCodes.OK).json({ success: true });
});

// @desc    Start a call
// @route   POST /api/chat/call
// @access  Private
const startCall = asyncHandler(async (req, res) => {
  const { conversationId, callType } = req.body;
  const userId = req.user._id;

  // Check if user is part of the conversation
  const conversation = await Conversation.findOne({
    _id: conversationId,
    participants: { $in: [userId] },
  }).populate('participants', '_id username profilePicture isOnline');

  if (!conversation) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Conversation not found');
  }

  // Create call message
  const message = await Message.create({
    conversation: conversationId,
    sender: userId,
    call: {
      type: callType,
      status: 'initiated',
    },
  });

  // Update conversation last message
  conversation.lastMessage = message._id;
  await conversation.save();

  const populatedMessage = await Message.findById(message._id)
    .populate('sender', 'username profilePicture');

  // Emit socket event to participants
  conversation.participants.forEach((participant) => {
    if (participant._id.toString() !== userId.toString()) {
      req.io.to(participant._id.toString()).emit('incomingCall', {
        conversationId,
        caller: req.user,
        callType,
        message: populatedMessage,
      });
    }
  });

  res.status(StatusCodes.CREATED).json(populatedMessage);
});

// @desc    End a call
// @route   PUT /api/chat/call/:messageId
// @access  Private
const endCall = asyncHandler(async (req, res) => {
  const { messageId } = req.params;
  const { status, duration } = req.body;
  const userId = req.user._id;

  const message = await Message.findById(messageId);

  if (!message) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Message not found');
  }

  // Check if user is part of the conversation
  const conversation = await Conversation.findOne({
    _id: message.conversation,
    participants: { $in: [userId] },
  });

  if (!conversation) {
    res.status(StatusCodes.NOT_FOUND);
    throw new Error('Conversation not found');
  }

  // Update call status
  message.call.status = status;
  message.call.duration = duration;
  await message.save();

  // Emit socket event to participants
  req.io.to(message.conversation.toString()).emit('callEnded', {
    messageId,
    status,
    duration,
  });

  res.status(StatusCodes.OK).json({ success: true });
});

module.exports = {
  getConversations,
  createConversation,
  createGroupConversation,
  getMessages,
  sendMessage,
  deleteMessage,
  startCall,
  endCall,
};