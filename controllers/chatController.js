const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const User = require('../models/User');
const logger = require('../middlewares/logger');
const { uploadToCloudinary } = require('../config/cloudinary');

// @desc    Start or get conversation
// @route   POST /api/chat/conversations
// @access  Private
exports.startConversation = async (req, res, next) => {
  try {
    const { participantId } = req.body;
    const userId = req.user.id;

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: [userId, participantId] },
    }).populate('participants', 'username profilePhoto status lastSeen');

    if (!conversation) {
      // Create new conversation
      conversation = await Conversation.create({
        participants: [userId, participantId],
      });

      conversation = await Conversation.findById(conversation._id).populate(
        'participants',
        'username profilePhoto status lastSeen'
      );
    }

    res.status(200).json({
      success: true,
      conversation,
    });
  } catch (error) {
    logger.error(`Chat Controller - Start Conversation Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get all conversations for a user
// @route   GET /api/chat/conversations
// @access  Private
exports.getConversations = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const conversations = await Conversation.find({
      participants: { $in: [userId] },
    })
      .populate('participants', 'username profilePhoto status lastSeen')
      .populate({
        path: 'lastMessage',
        select: 'content sender createdAt',
      })
      .sort('-updatedAt');

    res.status(200).json({
      success: true,
      count: conversations.length,
      conversations,
    });
  } catch (error) {
    logger.error(`Chat Controller - Get Conversations Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get single conversation
// @route   GET /api/chat/conversations/:id
// @access  Private
exports.getConversation = async (req, res, next) => {
  try {
    const conversation = await Conversation.findById(req.params.id)
      .populate('participants', 'username profilePhoto status lastSeen')
      .populate({
        path: 'messages',
        options: { sort: { createdAt: -1 }, limit: 20 },
        populate: {
          path: 'sender',
          select: 'username profilePhoto',
        },
      });

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found',
      });
    }

    // Check if user is part of the conversation
    if (!conversation.participants.some((p) => p._id.toString() === req.user.id)) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this conversation',
      });
    }

    res.status(200).json({
      success: true,
      conversation,
    });
  } catch (error) {
    logger.error(`Chat Controller - Get Conversation Error: ${error.message}`);
    next(error);
  }
};

// @desc    Send message
// @route   POST /api/chat/messages
// @access  Private
exports.sendMessage = async (req, res, next) => {
  try {
    const { conversationId, content, type = 'text' } = req.body;
    const senderId = req.user.id;

    // Check if conversation exists
    const conversation = await Conversation.findById(conversationId);

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found',
      });
    }

    // Check if user is part of the conversation
    if (!conversation.participants.includes(senderId)) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to send message in this conversation',
      });
    }

    let mediaUrl, mediaPublicId;

    // Handle file upload if present
    if (req.files && req.files.file) {
      const file = req.files.file;
      const result = await uploadToCloudinary(file.tempFilePath, 'vchat/messages');
      mediaUrl = result.url;
      mediaPublicId = result.public_id;
    }

    // Create message
    const message = await Message.create({
      conversation: conversationId,
      sender: senderId,
      content,
      type,
      media: mediaUrl ? { url: mediaUrl, publicId: mediaPublicId } : undefined,
    });

    // Update conversation's last message and updatedAt
    conversation.lastMessage = message._id;
    conversation.updatedAt = Date.now();
    await conversation.save();

    // Populate sender info
    const populatedMessage = await Message.findById(message._id).populate(
      'sender',
      'username profilePhoto'
    );

    res.status(201).json({
      success: true,
      message: populatedMessage,
    });
  } catch (error) {
    logger.error(`Chat Controller - Send Message Error: ${error.message}`);
    next(error);
  }
};

// @desc    Get messages in conversation
// @route   GET /api/chat/messages/:conversationId
// @access  Private
exports.getMessages = async (req, res, next) => {
  try {
    const { conversationId } = req.params;
    const { limit = 20, before } = req.query;

    // Check if conversation exists and user is part of it
    const conversation = await Conversation.findById(conversationId);

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found',
      });
    }

    if (!conversation.participants.includes(req.user.id)) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access these messages',
      });
    }

    // Build query
    const query = { conversation: conversationId };
    if (before) {
      query.createdAt = { $lt: before };
    }

    const messages = await Message.find(query)
      .populate('sender', 'username profilePhoto')
      .sort('-createdAt')
      .limit(parseInt(limit));

    res.status(200).json({
      success: true,
      count: messages.length,
      messages: messages.reverse(), // Return oldest first for UI
    });
  } catch (error) {
    logger.error(`Chat Controller - Get Messages Error: ${error.message}`);
    next(error);
  }
};

// @desc    Delete message
// @route   DELETE /api/chat/messages/:id
// @access  Private
exports.deleteMessage = async (req, res, next) => {
  try {
    const message = await Message.findById(req.params.id);

    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found',
      });
    }

    // Check if user is the sender
    if (message.sender.toString() !== req.user.id) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to delete this message',
      });
    }

    // Delete media from Cloudinary if exists
    if (message.media && message.media.publicId) {
      await deleteFromCloudinary(message.media.publicId);
    }

    await message.remove();

    res.status(200).json({
      success: true,
      message: 'Message deleted',
    });
  } catch (error) {
    logger.error(`Chat Controller - Delete Message Error: ${error.message}`);
    next(error);
  }
};

// @desc    Search users
// @route   GET /api/chat/search
// @access  Private
exports.searchUsers = async (req, res, next) => {
  try {
    const { query } = req.query;

    if (!query || query.length < 3) {
      return res.status(400).json({
        success: false,
        message: 'Search query must be at least 3 characters',
      });
    }

    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } },
      ],
      _id: { $ne: req.user.id }, // Exclude current user
    }).select('username profilePhoto status');

    res.status(200).json({
      success: true,
      count: users.length,
      users,
    });
  } catch (error) {
    logger.error(`Chat Controller - Search Users Error: ${error.message}`);
    next(error);
  }
};

// @desc    Update user status
// @route   PUT /api/chat/status
// @access  Private
exports.updateStatus = async (req, res, next) => {
  try {
    const { status } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { status },
      { new: true, runValidators: true }
    ).select('username profilePhoto status lastSeen');

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    logger.error(`Chat Controller - Update Status Error: ${error.message}`);
    next(error);
  }
};