const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const ErrorResponse = require('../utils/errorResponse');

// @desc    Get or create conversation
// @route   POST /api/chat/conversations
// @access  Private
exports.getOrCreateConversation = async (req, res, next) => {
  try {
    const { participantId } = req.body;

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: [req.user.id, participantId] },
      isGroup: false
    }).populate('participants', 'username profilePicture isOnline lastSeen');

    if (!conversation) {
      // Create new conversation
      conversation = await Conversation.create({
        participants: [req.user.id, participantId]
      });

      conversation = await Conversation.findById(conversation._id).populate(
        'participants',
        'username profilePicture isOnline lastSeen'
      );
    }

    res.status(200).json({
      success: true,
      data: conversation
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get all conversations for user
// @route   GET /api/chat/conversations
// @access  Private
exports.getConversations = async (req, res, next) => {
  try {
    const conversations = await Conversation.find({
      participants: { $in: [req.user.id] }
    })
      .populate('participants', 'username profilePicture isOnline lastSeen')
      .populate('lastMessage')
      .sort('-updatedAt');

    res.status(200).json({
      success: true,
      count: conversations.length,
      data: conversations
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get messages in conversation
// @route   GET /api/chat/messages/:conversationId
// @access  Private
exports.getMessages = async (req, res, next) => {
  try {
    const messages = await Message.find({
      conversation: req.params.conversationId,
      deletedFor: { $ne: req.user.id }
    })
      .populate('sender', 'username profilePicture')
      .populate('recipient', 'username profilePicture')
      .sort('createdAt');

    res.status(200).json({
      success: true,
      count: messages.length,
      data: messages
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Send message
// @route   POST /api/chat/messages
// @access  Private
exports.sendMessage = async (req, res, next) => {
  try {
    const { conversationId, recipientId, text, media } = req.body;

    // Check if conversation exists
    let conversation = await Conversation.findById(conversationId);

    if (!conversation) {
      conversation = await Conversation.create({
        participants: [req.user.id, recipientId],
        isGroup: false
      });
    }

    // Create message
    const message = await Message.create({
      conversation: conversation._id,
      sender: req.user.id,
      recipient: recipientId,
      text,
      media
    });

    // Update conversation's last message
    conversation.lastMessage = message._id;
    await conversation.save();

    // Populate sender and recipient details
    const populatedMessage = await Message.findById(message._id)
      .populate('sender', 'username profilePicture')
      .populate('recipient', 'username profilePicture');

    res.status(201).json({
      success: true,
      data: populatedMessage
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Delete message
// @route   DELETE /api/chat/messages/:messageId
// @access  Private
exports.deleteMessage = async (req, res, next) => {
  try {
    const message = await Message.findById(req.params.messageId);

    if (!message) {
      return next(new ErrorResponse('Message not found', 404));
    }

    // Check if user is the sender
    if (message.sender.toString() !== req.user.id) {
      return next(new ErrorResponse('Not authorized to delete this message', 401));
    }

    // For everyone or just for you?
    if (req.query.for === 'everyone') {
      await message.remove();
    } else {
      message.deletedFor.push(req.user.id);
      await message.save();
    }

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Create group conversation
// @route   POST /api/chat/groups
// @access  Private
exports.createGroup = async (req, res, next) => {
  try {
    const { name, participants } = req.body;

    if (participants.length < 2) {
      return next(new ErrorResponse('Group must have at least 2 participants', 400));
    }

    // Add current user to participants
    participants.push(req.user.id);

    const group = await Conversation.create({
      participants,
      isGroup: true,
      groupName: name,
      groupAdmin: req.user.id
    });

    const populatedGroup = await Conversation.findById(group._id)
      .populate('participants', 'username profilePicture isOnline lastSeen')
      .populate('groupAdmin', 'username profilePicture');

    res.status(201).json({
      success: true,
      data: populatedGroup
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update group info
// @route   PUT /api/chat/groups/:groupId
// @access  Private
exports.updateGroup = async (req, res, next) => {
  try {
    const { name, photo } = req.body;

    const group = await Conversation.findById(req.params.groupId);

    if (!group) {
      return next(new ErrorResponse('Group not found', 404));
    }

    // Check if user is admin
    if (group.groupAdmin.toString() !== req.user.id) {
      return next(new ErrorResponse('Not authorized to update this group', 401));
    }

    if (name) group.groupName = name;
    if (photo) group.groupPhoto = photo;

    await group.save();

    const populatedGroup = await Conversation.findById(group._id)
      .populate('participants', 'username profilePicture isOnline lastSeen')
      .populate('groupAdmin', 'username profilePicture');

    res.status(200).json({
      success: true,
      data: populatedGroup
    });
  } catch (err) {
    next(err);
  }
};