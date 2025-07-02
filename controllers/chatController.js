const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const User = require('../models/User');
const { upload } = require('../config/cloudinary');

// @desc    Get all conversations for a user
// @route   GET /api/chat/conversations
// @access  Private
exports.getConversations = async (req, res, next) => {
  try {
    const conversations = await Conversation.find({
      participants: req.user.id
    })
      .populate('participants', 'username avatar status')
      .populate('lastMessage')
      .sort({ updatedAt: -1 });

    res.status(200).json({
      success: true,
      count: conversations.length,
      data: conversations
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get or create conversation
// @route   POST /api/chat/conversations
// @access  Private
exports.getOrCreateConversation = async (req, res, next) => {
  try {
    const { recipientId } = req.body;

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: [req.user.id, recipientId], $size: 2 }
    })
      .populate('participants', 'username avatar status')
      .populate('lastMessage');

    if (!conversation) {
      // Create new conversation
      conversation = new Conversation({
        participants: [req.user.id, recipientId]
      });

      await conversation.save();

      // Populate the participants and lastMessage
      conversation = await Conversation.findById(conversation._id)
        .populate('participants', 'username avatar status')
        .populate('lastMessage');
    }

    res.status(200).json({
      success: true,
      data: conversation
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get messages in a conversation
// @route   GET /api/chat/messages/:conversationId
// @access  Private
exports.getMessages = async (req, res, next) => {
  try {
    const messages = await Message.find({
      conversation: req.params.conversationId
    })
      .populate('sender', 'username avatar')
      .sort({ createdAt: -1 })
      .limit(50);

    res.status(200).json({
      success: true,
      count: messages.length,
      data: messages.reverse()
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
    const { conversationId, text, isMedia } = req.body;
    let mediaUrl = '';

    if (isMedia && req.files) {
      const result = await upload.single('media')(req, res);
      mediaUrl = result.file.path;
    }

    // Create message
    const message = new Message({
      conversation: conversationId,
      sender: req.user.id,
      text: text || '',
      media: mediaUrl || undefined,
      isMedia: !!mediaUrl
    });

    await message.save();

    // Update conversation's last message
    await Conversation.findByIdAndUpdate(conversationId, {
      lastMessage: message._id,
      $inc: { unreadCount: 1 }
    });

    // Populate sender before sending
    const populatedMessage = await Message.findById(message._id).populate(
      'sender',
      'username avatar'
    );

    res.status(201).json({
      success: true,
      data: populatedMessage
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Mark messages as read
// @route   PUT /api/chat/messages/read/:conversationId
// @access  Private
exports.markAsRead = async (req, res, next) => {
  try {
    await Message.updateMany(
      {
        conversation: req.params.conversationId,
        sender: { $ne: req.user.id },
        read: false
      },
      { $set: { read: true } }
    );

    await Conversation.findByIdAndUpdate(req.params.conversationId, {
      $set: { unreadCount: 0 }
    });

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Start video call
// @route   POST /api/chat/call/start
// @access  Private
exports.startVideoCall = async (req, res, next) => {
  try {
    const { recipientId, isVideo } = req.body;

    // Find or create conversation
    let conversation = await Conversation.findOne({
      participants: { $all: [req.user.id, recipientId], $size: 2 }
    });

    if (!conversation) {
      conversation = new Conversation({
        participants: [req.user.id, recipientId]
      });
      await conversation.save();
    }

    // Create call message
    const message = new Message({
      conversation: conversation._id,
      sender: req.user.id,
      isCall: true,
      isVideoCall: isVideo,
      callStatus: 'initiated'
    });

    await message.save();

    // Update conversation's last message
    await Conversation.findByIdAndUpdate(conversation._id, {
      lastMessage: message._id
    });

    // Populate sender before sending
    const populatedMessage = await Message.findById(message._id).populate(
      'sender',
      'username avatar'
    );

    res.status(201).json({
      success: true,
      data: populatedMessage
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update call status
// @route   PUT /api/chat/call/update/:messageId
// @access  Private
exports.updateCallStatus = async (req, res, next) => {
  try {
    const { status } = req.body;

    const message = await Message.findByIdAndUpdate(
      req.params.messageId,
      { callStatus: status },
      { new: true }
    ).populate('sender', 'username avatar');

    res.status(200).json({
      success: true,
      data: message
    });
  } catch (err) {
    next(err);
  }
};